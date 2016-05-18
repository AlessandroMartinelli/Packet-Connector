/*
 * Copyright (C) 2016 Universita` di Pisa. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * common headers for nm2tcp gateway
 */

#define Q_ALIGN	8
/* TCP buffers 64k and above do not make a lot of difference */
#define MY_TCP_BUFLEN	(1<<18)
#define MY_Q_BUFLEN	(1000000)
#define MY_MAX_PKTLEN	9200 /* includes pkt_h and pad */

#define MY_CACHELINE    (128ULL)
#define ALIGN_CACHE     __attribute__ ((aligned (MY_CACHELINE)))

#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>	/* memcpy */
#include <signal.h>

#include <pthread.h>

#include <stdlib.h>	/* strtol */

_Static_assert(MY_Q_BUFLEN > 2 * MY_MAX_PKTLEN, "queue too small");

#ifdef ND
#undef ND
#undef RD
#undef D
#endif
#ifndef ND /* debug macros, from netmap */
#include <sys/time.h>

/* debug support */
#define ND(_fmt, ...) do {} while(0)
#define D(_fmt, ...)						\
    do {							\
	struct timeval _t0;					\
	gettimeofday(&_t0, NULL);				\
	fprintf(stderr, "%03d.%06d %-10.10s [%d] " _fmt "\n",	\
	    (int)(_t0.tv_sec % 1000), (int)_t0.tv_usec,		\
	    __FUNCTION__, __LINE__, ##__VA_ARGS__);		\
    } while (0)

/* Rate limited version of "D", lps indicates how many per second */
#define RD(lps, format, ...)					\
    do {							\
	static __thread int __t0, __cnt;			\
	struct timeval __xxts;					\
	gettimeofday(&__xxts, NULL);				\
	if (__t0 != __xxts.tv_sec) {				\
	    __t0 = __xxts.tv_sec;				\
	    __cnt = 0;						\
	}							\
	if (__cnt++ < lps) {					\
	    D(format, ##__VA_ARGS__);				\
	}							\
    } while (0)
#endif /* debugging macros */

#define SAFE_CALLOC(_sz)					\
    ({	int sz = _sz; void *p = sz>0 ? calloc(1, sz) : NULL;	\
	if (!p) { D("alloc error %d bytes", sz); exit(1); }	\
	 p;} )

/* default padding function */
static inline uint32_t
q_pad(uint32_t x)
{
	return (x + (Q_ALIGN - 1)) & ~(Q_ALIGN - 1);
}


/*
 * The header is used on the reliable channels with the input and
 * output loggers, and also for simplicity on the in_q and out_q.
 * For PALs, a single header precedes a number of PALs,
 * and seq is used for thread_id
 */
struct q_pkt_hdr {
    uint32_t seq;
    uint16_t type; /* data, PAL, wrap */
    uint16_t len;
};

enum { H_TY_NULL, H_TY_DATA, H_TY_PAL, H_TY_WRAP, H_TY_CLOSE };

static inline const char *
h_type(const void *_h)
{
    const struct q_pkt_hdr *h = _h;
    static const char *n[] = {"NULL", "DATA", "PAL", "WRAP", "CLOSE"};
    if (h == NULL) return "(null)";
    if (h->type > H_TY_CLOSE) return "(invalid)";
    return n[h->type];
}

/*
 * a queue which we can use for packets and PALs.
 * Each object in the queue is preceded by a q_pkt_hdr
 * which also includes type and length.
 * Packets+hdr are always contiguous, we leave room in the queue
 * so the last record can be a "WRAP" command go to back.
 * q_head == q_tail means empty queue. They are in separate
 * cache lines to avoid collisions, and are updated lazily;
 * producer and consumer have private copies of the pointers.
 * In particular:
 *    
 * to avoid too many cache collisions
 * 
 */
struct pkt_q {
    uint32_t	buflen;
    char *	buf; /* the payload */
    char name[80];

    /* producer's fields */
    uint64_t	prod_pkts ALIGN_CACHE; /* tx counter */
    uint64_t	prod_head_update;
    uint64_t	prod_tail_update;

    uint32_t	prod_head;      /* cached copy */
    uint32_t	prod_tail;      /* cached copy */

    /* consumer's fields */
    uint64_t	cons_pkts ALIGN_CACHE;
    uint64_t	cons_head_update;
    uint64_t	cons_tail_update;
    uint64_t	cons_empty_loop;
    uint64_t	cons_inq_empty;

    uint32_t	cons_head;	/* cached copy */
    uint32_t	cons_wr_head;	/* cached copy */
    uint32_t	cons_tail;	/* cached copy */

    /* shared fields */
    volatile uint32_t q_tail ALIGN_CACHE; /* producer writes here */
    volatile uint32_t q_end; /* producer writes here */

    volatile uint32_t q_head ALIGN_CACHE; /* consumer reads from here */
};

struct nmstate;

struct nmthread { /* per thread info */
    uint32_t id;

    struct nmstate *parent;
    struct nmthread *twin; /* same side, other direction */
    struct nmthread *peer; /* same direction, other side */
    pthread_t td_id;

    void *(*handler)(void *);
    uint32_t my_id;	/* 0.. n_threads - 1 */
    uint32_t ready;

    int listen_fd;
    int fd;
    uint32_t tcp_buflen;	/* for tcp I/O */
    char *tcp_buf; /* for tcp I/O */

    struct pkt_q *q; /* in or out */

    uint64_t pkt_count;
    uint64_t byte_count;
};

struct nmport {
    const char *name;
};


struct nmstate {
    uint32_t verbose;
    uint32_t n_chains; /* 1 or 2; threads are twice as many */

    const char *port_name[2]; /* always 2 */

    struct pkt_q q[2];	/* same as chains, contains queue */
    struct nmthread td[4];	/* twice as chains */
};


int do_socket(const char *addr, int nonblock, int *client);

uint32_t safe_write(int fd, const char *buf, uint32_t l);
// int safe_read(int fd, const char *buf, int l);
