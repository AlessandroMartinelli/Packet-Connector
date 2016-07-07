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

#ifndef PCQ_INDEX_T	/* possibly override index_t */
#define PCQ_INDEX_T uint32_t
#endif

#ifdef DO_STAT
#define ST(x)	x
#else
#define ST(x)
#endif

/*
 *	PCQ, a single producer, single consumer queue, lock free

    We define two classes here

	struct pcq_sem		a semaphore
	struct pcq_t		single sender, single receiver queue

    struct pcq_t {
	void **store;	 // the data buffer
	index_t prod_pi; // insert index, must be normalized with PCQ_IW()
	index_t cons_ci; // extract index, must be normalized with PCQ_IW()
	...
    }

    struct pcq_t *pcq_new(index_t capacity, index_t obj_size)
	Allocates, initializes and returns a queue.
	Actual allocation is the next power of 2 >= capacity
	obj_size = 0 creates two mmapped segments with given capacity,
		other sizes use regular malloc.

	obj_size = PCQ_OBJ_PTR creates entries that are void *
	Other sizes allocate objects with the desired size.

    index_t pcq_wait_space(struct pcq_t *q, index_t want) // producer
    index_t pcq_wait_data(struct pcq_t *q, index_t want)  // consumer
        Wait until there are 'want' indexes available,
	returns actual space available.
	want = PCQ_NONBLOCK will not block.

    index_t pcq_prod_advance(struct pcq_t *q, index_t have, bool force)
	Advance producer index by 'have' units. Do not publish the
	result to the consumer unless necessary or 'force' is true.

    index_t pcq_cons_advance(struct pcq_t *q, index_t have)
	Advance consumer index by 'have' units. Do not publish the result
	to the producer unless necessary.

    The following two are only valid if the queue is created with PCQ_OBJ_PTR

    bool pcq_push(struct pcq_t *q, void *p)
	pushes an entry in the queue
    void *pcq_push(struct pcq_t *q, void *p)
	pushes an entry in the queue

 */

#ifndef PCQ_ALIGN
#define PCQ_ALIGN     __attribute__ ((aligned (64)))
#endif

#ifndef ND
#define ND(_fmt, ...) do {} while(0)
#define D(_fmt, ...) do {} while (0)
#endif

#include <stdbool.h>
#include <stdint.h>	/* included by pthread */
#include <stdlib.h>	/* malloc and free */
#include <unistd.h>	/* usleep */
#include <sys/mman.h>	/* mmap */
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

#include <pthread.h>

typedef PCQ_INDEX_T index_t;
#define PCQ_IW(expr)	((index_t)(expr))	/* force to base type */
#define PCQ_OBJ_PTR	PCQ_IW(~0)	/* special size for void * */
#define PCQ_NONBLOCK	PCQ_IW(~0)	/* special size for non blocking * */

/*
 * Semaphore implemented with mutex and condition variables
 */
struct pcq_sem {
    pthread_mutex_t lock;
    pthread_cond_t cv;
    int flag;
    /* debugging info below */
    const char *name;
    uint32_t wait_count, signal_count;
};

static inline void pcq_sem_init(struct pcq_sem *s, const char *name)
{
    pthread_mutex_init(&s->lock, NULL);
    pthread_cond_init(&s->cv, NULL);
    s->flag = 0;
    s->name = name;
    s->wait_count = s->signal_count = 0;
}

static inline void pcq_sem_wait(struct pcq_sem *s)
{
    ND(1, "wait on %s started %d", s->name, s->wait_count);
    pthread_mutex_lock(&s->lock);
    while (s->flag == 0) {
	pthread_cond_wait(&s->cv, &s->lock);
    }
    s->flag = 0;
    pthread_mutex_unlock(&s->lock);
    ND(1,"wait on %s completed %d", s->name, s->wait_count);
    s->wait_count++;
}

static inline void pcq_sem_signal(struct pcq_sem *s)
{
    ND(1, "signal on %s started %d", s->name, s->signal_count);
    pthread_mutex_lock(&s->lock);
    s->flag = 1;
    pthread_cond_signal(&s->cv);
    pthread_mutex_unlock(&s->lock);
    ND(1, "signal on %s completed %d", s->name, s->signal_count);
    s->signal_count++;
}

/* the queue */
struct pcq_t {
    /* the store size  is a power of 2 and <= half of index_t.
     * store_mask is used for normalization, one less the size.
     * capacity may be less than store_size
     */
    // TODO: maybe store_mast "must be a power of 2 - 1;
    index_t store_mask;	/* must be a power of 2 <= half of index_t */
    index_t capacity;	/* must be <= store_size XXX right now only == */
    uint32_t obj_size;	/* size of individual objects */
    void **store;
    char name[128];

    PCQ_ALIGN		/*-- fields exported by the producer --*/
    volatile index_t __prod_index; /* next entry to use */
    volatile index_t prod_event; /* notify when cons_index goes past this */

    PCQ_ALIGN		/*-- producer local data --*/
    index_t prod_ci;	/* local copy of cons_index (may be behind) */
    index_t prod_pi;	/* local copy of prod_index (may be ahead) */
    uint64_t prod_space_stat[6];

    PCQ_ALIGN		/*-- fields exported by the consumer --*/
    volatile index_t __cons_index; /* next free entry */
    volatile index_t cons_event; /* notify when prod_index goes past this */

    PCQ_ALIGN		/*-- consumer local data --*/
    index_t cons_pi;	/* local copy of prod_index (may be behind) */
    index_t cons_ci;	/* local copy of cons_index (may be ahead) */
    volatile uint64_t cons_data_stat[6];

    PCQ_ALIGN		/*-- producer semaphore --*/
    struct pcq_sem  prod_sem;
    PCQ_ALIGN		/*-- consumer semaphore */
    struct pcq_sem cons_sem;
};

/*
 * create queue. obj_size:
 *	0 -> mmap, circular buffer with mmap
 *	PCQ_IW(~0) -> void *, linear buffer
 *	others -> linear buffer
 */

struct pcq_t *pcq_new(index_t capacity, index_t obj_size)
{
    struct pcq_t *ret = NULL;
    size_t sz;
    index_t act_sz = 1U<<(8*sizeof(index_t) - 1);

    D("Requested capacity is 0x%x, max 0x%x", capacity, act_sz);
    // XXX fix, accept capacity not power of 2
    while (act_sz > 4096 && capacity <= act_sz / 2)
	act_sz /= 2;
    if (capacity < 1 || capacity > act_sz) {
	D("invalid queue size %d", capacity);
	goto fail;
    }
    D("Requested capacity is 0x%x, actual 0x%x", capacity, act_sz);
    ret = calloc(1, sizeof(*ret));
    if (ret == NULL)
	goto fail;
    ret->store_mask = act_sz - 1;
    ret->capacity = capacity; /* XXX maybe less ? */
    ret->obj_size = obj_size;
    pcq_sem_init(&ret->prod_sem, "prod");
    pcq_sem_init(&ret->cons_sem, "cons");
    /* all indexes are set to 0 */

    if (obj_size == PCQ_OBJ_PTR) {
	sz = act_sz * sizeof(void *);
	D("assuming objects are void *, sz is %d", (int)sizeof(void *));
    } else {
	sz = act_sz * obj_size;
    }
    if (obj_size != 0) { /* regular, calloc based */
	D("memory based allocation of %d bytes, %d byte objects", (int)sz, (int)(sz/act_sz));
	ret->store = calloc(1, sz);
	if (ret->store == NULL)
	    goto fail;
    } else { /* cbuf, use mmap */
	char fn[] = "/tmp/pcq-XXXXXX";  /* exactly 6 X */
	int fd = mkstemp(fn); /* create a filename */
	char *addr, *m;

	sz = act_sz;
	D("double mmap one-byte objects");
	if (fd < 0 || unlink(fn) || ftruncate(fd, sz)) {
	    D("open, link or truncate %s failed, fd %d, sz %d", fn, fd, (int)sz);
	    goto fail;
	}
	/* first mmap to reserve a sufficiently large address block */
	m = mmap(NULL, sz*2, PROT_READ|PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (m == MAP_FAILED) {
	    D("file mmap failed");
	    goto fail;
	}
	m[0] = 0x55;
	m[sz] = 0x5a;
	D("store has %x %x", m[0], m[sz]);
	addr = mmap(m, sz, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED, fd, 0);
	if (addr != m) {
	    D("first mmap failed");
	    munmap(m, 2*sz);
	    goto fail;
	}
	m[0] = 0xdd;
	D("store has %x %x", m[0], m[sz]);
	addr = mmap(m + sz, sz, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED, fd, 0);
	if (addr != m + sz) {
	    D("second mmap failed");
	    munmap(m, sz);
	    goto fail;
	}
	D("store has %x %x", m[0], m[sz]);
	ret->store = (void **)m;
	close(fd); /* XXX can we do it here ? */
    }
    return ret;
fail:
    if (ret)
	free(ret);
    return NULL;
}

static inline void pcq_delete(struct pcq_t *q)
{
    if (q->obj_size == 0) {
	munmap(q->store, q->capacity);
	munmap((char *)(q->store) + q->capacity, q->capacity);
    } else {
	free(q->store);
    }
    free(q);
}

/* normalize index to 0..store_mask */
static inline index_t pcq_ofs(struct pcq_t *q, index_t i)
{
    return i & q->store_mask;
}


/*
 * used = PCQ_IW(prod_index - cons_index) is always <= capacity
 * If we need X slots, then we need (considering wraparounds)
 *	PCQ_IW(prod_index - cons_index) <= capacity - X
 * where the term is the number of used slots.
 *
 * If X=1, the above equals PCQ_IW(prod_index - cons_index) != capacity
 *
 * The wakeup point must be prod_event + capacity >= prod_index + want - 1 or
 *    prod_index + want - 1 - capacity <= prod_event < prod_index
 * The closer to prod_index, the later is the notification.
 */

static inline bool prod_has_space(struct pcq_t *q, int i, index_t want)
{
    ST(q->prod_space_stat[i]++;)
    if (i != 0) {	/* refresh from exported value */
	q->prod_ci = q->__cons_index;
    }
    return PCQ_IW(q->prod_pi - q->prod_ci) <=  q->capacity - want;
}

#define pcq_barrier() asm volatile("mfence":::"memory") // XXX x86 specific

/* advance by the desired amount, notify a possibly sleeping consumer */
static inline void pcq_prod_notify(struct pcq_t *q)
{
    index_t ce, old = q->__prod_index;

    q->__prod_index = q->prod_pi;
    pcq_barrier(); // XXX MANDATORY
    ce = q->cons_event;
    /* check if we cross cons_event, notify if needed */
    if (PCQ_IW(q->prod_pi - ce - 1) < PCQ_IW(q->prod_pi - old)) {
	ND("notify prod->cons old %x ce %x pi %x", old, ce, q->prod_pi);
	pcq_sem_signal(&q->cons_sem);
	ST(q->cons_data_stat[5]++;)
    }
}

static inline void pcq_prod_advance(struct pcq_t *q, index_t have, bool force)
{
    q->prod_pi += have;
    if (force)
	pcq_prod_notify(q);
}

static inline index_t pcq_wait_space(struct pcq_t *q, index_t want)
{
    while (true) {
	if (prod_has_space(q, 0, want)) /* first, cached value */
	    break;
	if (prod_has_space(q, 1, want)) /* update cons_index and retry */
	    break;
	/* export prod_index, set wakeup point, double check.
	 * Can ignore 'want' as we will re-check after the wakeup
	 */
	q->prod_event = PCQ_IW(q->prod_ci + PCQ_IW(q->prod_pi - q->prod_ci)/2);
	//q->prod_event = PCQ_IW(q->prod_pi - 1);
	pcq_prod_notify(q); // includes prod_index update and mandatory barrier
	if (prod_has_space(q, 2, want)) /* double check. */
	    break;
	if (want == PCQ_NONBLOCK) // non blocking
	    break;
	ST(q->prod_space_stat[3]++;)
	/* not enough space, block */
	ND("block prod pci %x pe %x pi %x", q->prod_ci, q->prod_event, q->prod_pi);
	pcq_sem_wait(&q->prod_sem);
	q->prod_ci = q->__cons_index; /* refresh from exported value */
    }
    return PCQ_IW(q->prod_ci + q->capacity - q->prod_pi);
}

/*
 * return true if 'want' units are available, refresh cons_pi if i > 0
 */
static inline bool cons_has_data(struct pcq_t *q, int i, index_t want)
{
    ST(q->cons_data_stat[i]++;)
    if (i != 0) {	/* refresh from exported value */
	q->cons_pi = q->__prod_index;
    }
    return PCQ_IW(q->cons_pi - q->cons_ci) >= want;
}

/* update cons_index, send a notification if we cross prod_event. */
static inline void pcq_cons_notify(struct pcq_t *q)
{
    index_t pe, old = q->__cons_index;

    q->__cons_index = q->cons_ci;
    pcq_barrier();
    pe = q->prod_event;
    /* check if we cross prod_event, notify if needed */
    if (PCQ_IW(q->cons_ci - pe - 1) < PCQ_IW(q->cons_ci-old)) {
	ND("notify cons->prod old %x pe %x ci %x", old, pe, q->cons_ci);
	pcq_sem_signal(&q->prod_sem);
	ST(q->prod_space_stat[4]++;)
    }
}

/* release slots, notify if queue perceived empty */
// XXX TODO check if earlier notifications are useful
static inline void pcq_cons_advance(struct pcq_t *q, index_t have)
{
    q->cons_ci += have;
    if (PCQ_IW(q->cons_pi - q->cons_ci) == 0) // XXX
	pcq_cons_notify(q);
}

// TODO: maybe want are packet, not bytes.
/* Waits until there are at least "want" bytes to read, and return the number of
 * bytes to read. It may also be used as non-blocking (want = 0) for discovering
 * the number of bytes to read. */
static inline index_t pcq_wait_data(struct pcq_t *q, index_t want)
{
    while (true) {
	if (cons_has_data(q, 0, want)) /* use cached value */
	    break;
	if (cons_has_data(q, 1, want)) /* refresh prod_index and retry */
	    break;
	usleep(1); /* short sleep and retry. Very effective with slow producer */
	if (cons_has_data(q, 2, want))
	    break;
	/* no data, publish and request wakeup */
	q->cons_event = q->cons_ci + want - 1;
	pcq_cons_notify(q); // XXX includes cons_index update and mandatory barrier
	if (cons_has_data(q, 3, want)) /* double check */
	    break;
	if (want == PCQ_NONBLOCK)
	    break; // non blocking
	ND("block cons cpi %x ce %x ci %x", q->cons_pi, q->cons_event, q->cons_ci);
	ST(q->cons_data_stat[4]++;)
	pcq_sem_wait(&q->cons_sem);
	q->cons_pi = q->__prod_index; /* refresh from exported value */
    }
    return q->cons_pi - q->cons_ci;
}

/* The following two only make sense for queues of pointers.
 * Operations take 2-3ns, the final advance+barrier adds another 13-16ns.
 */
static inline bool pcq_push(struct pcq_t *q, void *d)
{
    if (q->obj_size != PCQ_OBJ_PTR)
	return false;
    pcq_wait_space(q, 1 /* want */);
    q->store[pcq_ofs(q, q->prod_pi)] = d;
    pcq_prod_advance(q, 1, ((uintptr_t)d & 1) == 0);
    return true;
}

// TODO: I'm afraid 1 may be a packet, not a byte. This also since store is a void**
/* Wait until there is at least 1 byte to read, then it return it and advance
 * cons_ci */
static inline void * pcq_pull(struct pcq_t *q)
{
    void *ret;
    if (q->obj_size != PCQ_OBJ_PTR)
	return NULL; /* unsupported */
    pcq_wait_data(q, 1 /* want */);
    ret = q->store[pcq_ofs(q, q->cons_ci)];
    pcq_cons_advance(q, 1);
    return ret;
}
