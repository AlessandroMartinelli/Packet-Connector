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
 * common headers for packet connectors
 */

#define _GNU_SOURCE     /* pthread_setaffinity_np */
#include <sched.h>  // must be early on */
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>	/* memcpy */
#include <signal.h>

/*arp packet generation headers*/
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>

#ifdef WITH_NETMAP
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#endif

#ifdef WITH_PCAP
#include <pcap.h>
#endif

/* XXX where ? */
#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

#define MY_MAX_PKTLEN	10000 /* includes pkt_h and pad */
#define Q_ALIGN	8
/* default padding function */
static inline uint32_t q_pad(uint32_t x)
{
    return (x + (Q_ALIGN - 1)) & ~(Q_ALIGN - 1);
}



#include <pthread.h>

/* scheduling and setaffinity */
#ifdef __FreeBSD__
#include <pthread_np.h> /* pthread w/ affinity */
#include <sys/cpuset.h> /* cpu_set */
#define pthread_setname_np pthread_set_name_np
#endif /* __FreeBSD__ */

#ifdef linux
#define cpuset_t        cpu_set_t
#endif

#ifdef __APPLE__

#include <mach/mach.h>
#include <pthread.h>

static inline void _psn(void *foo, const char *n) { (void)foo; pthread_setname_np(n); }
#define pthread_setname_np _psn

#define cpu_set_t       uint32_t

#define cpuset_t        uint64_t        // XXX
static inline void CPU_ZERO(cpuset_t *p)
{
    *p = 0;
}

static inline void CPU_SET(uint32_t i, cpuset_t *p)
{
    *p |= 1<< (i & 0x3f);
}

static inline int CPU_ISSET(uint32_t i, cpuset_t *p)
{
    return (*p & (1<< (i & 0x3f)) );
}

/*
 * simplified version, we only bind to one core or all cores
 * if the mask contains more than 1 bit
 */
static inline int
pthread_setaffinity_np(pthread_t thread, size_t cpusetsize,
                           cpuset_t *cpu_set)
{
    thread_port_t mach_thread;
    int core, lim = 8 * cpusetsize;

    for (core = 0; core < lim; core++) {
	if (CPU_ISSET(core, cpu_set)) break;
    }
    if (core == lim || (*cpu_set & ~(1 << core)) != 0) {
	core = -1;
    }
    printf("binding to core %d 0x%lx\n", core, (u_long)*cpu_set);
    thread_affinity_policy_data_t policy = { core+1 };
    mach_thread = pthread_mach_thread_np(thread);
    thread_policy_set(pthread_mach_thread_np(thread), THREAD_AFFINITY_POLICY,
	(thread_policy_t)&policy, 1);
    return 0;
}

#define sched_setscheduler(a, b, c)     (1) /* error */

#include <libkern/OSAtomic.h>

#define clock_gettime(a,b)      \
        do {struct timespec t0 = {0,0}; *(b) = t0; } while (0)
#endif /* APPLE */

void runon(const char *,int);

#include <stdlib.h>	/* strtol */


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

/* set a 64_bit timestamp in nanoseconds */
static inline uint64_t ts64(void)
{
    struct timeval t;
    gettimeofday(&t, NULL);
    return (t.tv_usec * 1000 + 1000000000UL*t.tv_sec);
}

#define SAFE_CALLOC(_sz)	/* unused */			\
    ({	int sz = _sz; void *p = sz>0 ? calloc(1, sz) : NULL;	\
	if (!p) { D("alloc error %d bytes", sz); exit(1); }	\
	 p;} )


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

struct pconn_state;

struct my_td { /* per thread info */
    uint32_t id;
    char name[80];
    uint32_t core; /* which core is used to run us */

    struct pconn_state *parent;
    struct my_td *twin; /* same side, other direction */
    struct my_td *peer; /* same direction, other side */
    pthread_t td_id;

    void *(*handler)(void *); /* main thread handler */
    void *(*pr_stat)(void *); /* stat printer */
    volatile uint32_t ready; /* 0: not ready; 1: ready; 2: complete; 3: joined */

    uint32_t pkt_len;

    /* private fields */
    uint64_t datalen;
    void *data;

    int listen_fd;
    int fd;
    
    pcap_t* pcap_fd;

    struct pcq_t *q; /* in or out */
};

struct pconn_port {
    const char *name;
};

struct pconn_state { /* global arguments and resources */
    uint32_t verbose;
    uint32_t n_chains; /* 1 or 2; threads are twice as many */
    uint32_t qlen;	/* in slots/bytes */
    uint32_t obj_size;
    uint32_t mode;	/* in bytes */
    uint32_t base_core;	/* first core to use */

    struct pconn_port port[2];
    struct pcq_t *q[2];	/* same as chains, contains queue */
    struct my_td td[4];	/* twice as chains */
};


int do_socket(const char *addr, int nonblock, int *client);

uint32_t safe_write(int fd, const char *buf, uint32_t l);
// int safe_read(int fd, const char *buf, int l);
