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

#ifdef WITH_NETMAP
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#endif

#include "pconn.h"

#include "pcq.h"

#if 0 /* description */
This is a general purpose command that connects two packet streams,
possibly bidirectionally. The streams can be
- tcp
- netmap (later)
- pcap (later)

For each direction, input and output are handled by separate threads,
with a large queue in the middle. Thus, a total of 4 threads handles
a bidirectional communication.

#endif /* description */

/* statistics and local data */
struct test_t {
    struct pcq_t dumpq;	/* a copy of the queue */
    struct pcq_t *q; /* pointer to the original queue */
    volatile uint64_t bctr; /* byte counter transfered */
    volatile uint64_t pctr; /* packet counter transfered */
    volatile uint64_t bctr_old;	/* saved value */
    volatile uint64_t pctr_old;	/* saved value */
    volatile uint64_t stop;
    uint64_t ts;
};

static void *f_test_stats(void *_f);

static void
my_td_init(struct my_td *t)
{
    struct test_t *d;

    D("initializing thread %d", t->id);
    runon(t->name, t->core);
    t->datalen = sizeof(struct test_t);
    d = t->data = calloc(1, sizeof (*d));
    d->ts = ts64();
    d->q = t->q;
    d->dumpq = *t->q;
    t->pr_stat = f_test_stats;
}

static void *
f_test_stats(void *_f)
{
    struct my_td *t = _f;
    struct test_t *d = t->data;
    uint64_t now = ts64();
    double dt = (now - d->ts)/1e9;

#define X(v) (u_long)(d->q->v - d->dumpq.v)
    D("T%d %.3f s %.3e tps %.3e Bps %lu %lu %lu %lu %lu - %lu %lu %lu %lu %lu %lu",
		t->id,
		dt, (double)(d->pctr - d->pctr_old)/dt,
		(double)(d->bctr - d->bctr_old)/dt,
		X(prod_space_stat[0]), X(prod_space_stat[1]), X(prod_space_stat[2]),
		X(prod_space_stat[3]), X(prod_space_stat[4]),
		X(cons_data_stat[0]), X(cons_data_stat[1]), X(cons_data_stat[2]),
		X(cons_data_stat[3]), X(cons_data_stat[4]), X(cons_data_stat[5])
		);
    if (d->pctr == d->pctr_old) {
	D("  blocked c_pi %x _pi %x l_pi %x pe %x p_ci %x _ci %x l_ci %x ce %x",
		d->q->cons_pi, d->q->__prod_index, d->q->prod_pi, d->q->prod_event,
		d->q->prod_ci, d->q->__cons_index, d->q->cons_ci, d->q->cons_event);
    }
    d->stop++;
    d->bctr_old = d->bctr;
    d->pctr_old = d->pctr;
    d->dumpq = *(d->q);
    d->ts = now;
    return NULL;
}


static char **g_argv; /* we save argv here */
static void
usage(void)
{
    D("\n\tusage: %s [-v] [-2] port1 port2\n"
        "\tports can be netmap:*, vale* or tcp:host:port\n"
        "\thost and port are resolved with the resolver", g_argv[0]);
    exit(1);
}


static void
td_wait_ready(struct pconn_state *f)
{
    uint32_t i;

    /* wait for first two threads to be ready */
    for (i = 0; i < f->n_chains; ) {
	if (!f->td[i].ready) {
	    D("thread %d not ready, wait...", i);
	    usleep(1000);
	    continue;
	}
	i++;
    }
    D("+++ main threads ready");
}


/*
 * The main function (id < 2) does the open,
 * then runs the second thread if needed
 */
static void *
f_netmap_body(void *_f)
{
    struct my_td *t = _f;
    struct pconn_state *f = t->parent;

#ifndef WITH_NETMAP
    (void)f;
    (void)t;
    D("netmap unsupported");
#else
    if (t->id < 2) { /* first and second do the open part */
	t->nm_desc = nm_open(f->port[f->id].name, NULL, 0, NULL);
	if (f->n_chains == 2) {
	    t[2].id = t->id + 2;
	    pthread_create(&t[2].td_id, NULL, t[2].handler, t+2);
	}
    }
    D("thread %p terminating", t);
#endif
    return NULL;
}


/* read from socket into the queue */
static void *
f_tcp_read(struct my_td *t)
{
    struct pcq_t *q = t->q;
    char *buf = (char *)(q->store);
    struct test_t *d = t->data;
    index_t rd = q->prod_pi; /* socket read position */
    /* prod_pi points to a packet header;
     * rd >= prod_pi is where we read new data
     */
    D("+++ start reading from input tcp, id %d q %p ready %d", t->id, t->q, t->ready);
    while (t->ready == 1) {
	struct q_pkt_hdr *h; /* h points to a descriptor at buf + prod_pi */
	index_t need, avail, have = PCQ_IW(rd - q->prod_pi);
	int nread;

	/* Blocking wait for space. We must be greedy, as the queue is lazy */
	avail = pcq_wait_space(q, q->capacity/4);

	nread = read(t->fd, buf + pcq_ofs(q, rd), avail - have);
	ND( "NNN read %d bytes out of %d, avail %d", nread, avail - have, avail);
	if (nread <= 0)  {
	    D("--- nread %d out of %d, avail %d, circuit dead, finish", nread, avail - have, avail);
	    break;
	}
	rd += nread;
	d->bctr += nread;
	d->pctr += 1;
	avail = nread + have;
	while (true) {
	    h = (struct q_pkt_hdr *)(buf + pcq_ofs(q, q->prod_pi));
	    if (avail < sizeof(*h))
		break;
	    need = q_pad(sizeof(*h) + h->len);
	    if (avail < need)
		break;
	    pcq_prod_advance(q, need, false); /* do not notify */
	    avail -= need;
	    if (h->type == H_TY_CLOSE) {
		D("--- founc CLOSE packet, finish");
		t->ready = 2;
		break;
	    }
	}
	pcq_prod_notify(q);
    }
    D("WWW closing fd, rd %d local %d", rd, q->prod_pi);
    close(t->fd);
    t->fd = t->twin->fd = -1; /* same side */
    t->ready = t->twin->ready = 2;  /* TODO_ST: maybe in server mode the state should be set to 0 ?  */
    return NULL;
}


/*
 * read from queue, push to tcp
 */
static void *
f_tcp_write(struct my_td *t)
{
    struct pcq_t *q = t->q;
    char *buf = (char *)(q->store);
    struct test_t *d = t->data;

    D("III start thread %d", t->id);
    while (t->ready == 1)  {
	struct q_pkt_hdr *h;
	index_t need, avail, cur = q->cons_ci;

	/* Fetch one packet from the queue. Eventually we'll get it */
	avail = pcq_wait_data(q, sizeof(*h));
        h = (struct q_pkt_hdr *)(buf + pcq_ofs(q, cur));
        need = q_pad(sizeof(*h) + h->len);
	if (avail < need)
	    avail = pcq_wait_data(q, need);

	ND("start at ofs %x", cur);
	while (true) {
	    // XXX optional check type
	    cur += need;
	    avail -= need;
	    if (h->type == H_TY_CLOSE) {
		D("--- found close");
		t->ready = 0;
		break;
	    }
	    /* prepare for next packet, break if not available */
	    h = (struct q_pkt_hdr *)(buf + pcq_ofs(q, cur));
	    if (avail < sizeof(*h))
		break;
	    need = q_pad(sizeof(*h) + h->len);
	    if (avail < need) {
		D("ofs %x need %x have %x", cur, need, avail);
		break;
	    }
	}
	need = cur - q->cons_ci; /* how many bytes to send */
	if (need == 0) {
	    D("should not happen, empty block ?");
	    continue;
	}
	cur = safe_write(t->fd, buf + pcq_ofs(q, q->cons_ci), need);
	if (cur != need) { // short write, circuit closed
	    RD(5, "short write want %d have %d", need, cur);
	    break;
	}
	d->bctr += need;
	d->pctr += 1;
	pcq_cons_advance(q, need); /* lazy notify */
    }
    D("WWW closing fd");
    close(t->fd);
    t->fd = t->twin->fd = -1;
    t->ready = t->twin->ready = 2;  /* TODO_ST: maybe in server mode the state should be set to 0 ?  */
    return NULL;
}


static void *
f_tcp_body(void *_f)
{
    struct my_td *t = _f;
    struct pconn_state *f = t->parent;
    void *(*cb)(struct my_td *) = (t->id == 0 || t->id == 3) ? f_tcp_read : f_tcp_write;

    snprintf(t->name, sizeof(t->name) - 1, "%s%d",
	t->id == 0 || t->id == 3 ? "read" : "write", t->id);
    my_td_init(t);

    if (t->q->capacity < 8 * MY_MAX_PKTLEN) {
	D("TERMINATE, queue too short, need at least %d bytes", 8 * MY_MAX_PKTLEN);
	t->ready = t->peer->ready = 2;
	return NULL;
    }
    D("start thread %d", t->id);
    /* complete initialization */

    if (t->id < 2) { /* first and second open the tcp connection */
        int client = 1;
	t->listen_fd = -1;
	t->fd = do_socket(f->port[t->id].name + 4, 0, &client); // client. Names start with tcp:
	if (t->fd < 0) {
	    D("*** cannot to %s", f->port[t->id].name);
	    return NULL;
	}
	D("mode for %d is %s", t->id, client ? "client" : "server");
	if (!client) {
	    t->listen_fd = t->fd;
	    t->fd = -1;
	}
	t->ready = t->twin->ready = 1;
	if (f->n_chains == 2) {
	    t[2].fd = t->fd;
	    t[2].listen_fd = t->listen_fd;
	    // pthread_create(&t[2].td_id, NULL, t[0].handler, t+2);
	}
    }

    td_wait_ready(t->parent); /* wait for client threads to be ready */
    if (t->listen_fd == -1) { /* client mode, connect and done */
	D("-- running %d in client mode", t->id);
	cb(t);
	t->ready = t->twin->ready = 2;
    } else { /* server mode, base does accept, twin waits for fd */
    	for (;;) {
	    D("III running %d in server mode on fd %d", t->id, t->listen_fd);
            printf("id=%d, twin fd is %d\n",t->id,t->twin->fd);
	    t->fd = t->id < 2 ? accept(t->listen_fd, NULL, 0) : t->twin->fd;
	    if (t->fd < 0) {
		D("accept failed, retry");
		sleep(1);
	    } else {
		D("accept for %d successful, start", t->id);
		t->ready = t->twin->ready = 1;
		cb(t);
		t->ready = 0;
	    }
	    D("III closing %d in server mode", t->id);
	}
    }
    if (t->id < 2 && f->n_chains == 2) {
        pthread_join(t[2].td_id, NULL);
    }
    return NULL;
}

static void *
f_test_body(void *_f)
{
    struct my_td *t = _f;
    struct pconn_state *f = t->parent;
    struct test_t *d;
    struct pcq_t *q = t->q;
    int mode = f->mode;
    int out_fd=-1, in_fd=-1;
    int ret;
    char fname[15];
    char randchar;
    index_t tmp_index;
    
    snprintf(t->name, sizeof(t->name) - 1, "%s%d",
	t->id == 0 || t->id == 3 ? "prod" : "cons", t->id);
    my_td_init(t);
    d = t->data;
    t->ready = 1;
    D("now thread %d ready", t->id);
    /* body */

    if(t->id==1 || t->id==2){
        sprintf(fname,"out_tid%d.raw", t->id);
        out_fd = open(fname, O_WRONLY|O_CREAT,0666);
    } else {
        sprintf(fname,"in_tid%d.raw", t->id);
        in_fd = open(fname, O_WRONLY|O_CREAT,0666);
    }
    srand(time(NULL));

    D("---- running in mode %d id %d store %p -------", mode, t->id, q->store);
    
    /* test thread stops when: 
       - if producer: after having emitted 20 stats 
       - if consumer: never */
    while (t->ready && (d->stop < 20 || (t->id==1 || t->id==2))) {
	struct q_pkt_hdr *h;
	char *buf = (char *)(q->store);

	if (t->id == 1 || t->id == 2) { /* consumer */
            tmp_index = q->cons_ci;
	    index_t avail, need;
	    h = (struct q_pkt_hdr *)(buf + pcq_ofs(q, q->cons_ci));

	    switch (mode) {
	    case 0: /* push/pull */
		pcq_pull(q);
		break;

	    case 1: /* wait 1, advance avail */
		avail = pcq_wait_data(q, 1);
		pcq_cons_advance(q, avail);
		break;

	    case 2: /* wait 1000, advance 1000 */
		pcq_wait_data(q, 1000);
		pcq_cons_advance(q, 1000);
		break;

	    case 3: /* read data from the queue */
		avail = pcq_wait_data(q, sizeof(*h));
		ND("read from %p", h);
		if (h->type == H_TY_CLOSE) {
		    D("consumer terminated");
		    goto done;
		}
		need = q_pad(sizeof(*h) + h->len);
		if (avail < need)
		    pcq_wait_data(q, need);
                
                /* writes the received packet also on the file */
                ret = write(out_fd, buf + pcq_ofs(q,tmp_index), sizeof(*h) + h->len);
                if(ret == -1){
                    D("File write error during test output");
                }
                
		pcq_cons_advance(q, need);
		d->bctr+= h->len;
		break;
	    }
	} else { /* producer */
	    index_t want, avail;
	    h = (struct q_pkt_hdr *)(buf + pcq_ofs(q, q->prod_pi));

            tmp_index = q->prod_pi;
            
	    switch (mode) {
	    case 0: /* push/pull */
		pcq_push(q, (void *)(uintptr_t)((d->pctr & 0xff) != 0) );
		break;

	    case 1: /* wait 1, advance 1 */
	    case 2:
		pcq_wait_space(q, 1);
		pcq_prod_advance(q, 1, (d->pctr & 0xff) == 0);
		break;

	    case 3: /* write a packet */
		want = q_pad(sizeof(*h) + t->pkt_len);
                
		avail = pcq_wait_space(d->q, want);
		ND("write at %p", h);
		*h = (struct q_pkt_hdr){ d->pctr, H_TY_DATA, t->pkt_len};
                
                /*fills the memory with random characters */
                randchar = rand() % 256;
		memset(h+1, randchar, t->pkt_len);
		d->bctr += h->len;
                
                /* writes the generated packet also to the file */
                ret = write(in_fd, buf + pcq_ofs(q,tmp_index), sizeof(*h) + h->len);
                if(ret == -1){
                    D("File write error during test input");
                }
                
		pcq_prod_advance(q, want, (d->pctr & 0xff) != 0);
		break;
	    }
	}
	d->pctr++;
    }
done:
    /* exiting */
    if(t->id==1 || t->id==2){
        close(out_fd);
    } else {
        close(in_fd);
    }
    t->ready = 2;
    D("now thread %d exiting", t->id);
    return NULL;
}

struct _sp {
	const char *prefix;
	void *(*handler)(void *);
};

struct _sp h[] = {
	{"test", f_test_body},
	{"netmap:", f_netmap_body},
	{"vale", f_netmap_body},
	{"tcp:", f_tcp_body},
	{ NULL, NULL }
};

/*
 * main program: setup initial parameters and threads, run
 */
int
main(int ac, char **av)
{
    struct pconn_state _f, *f = &_f;
    uint32_t i;
    int ch;
    struct my_td *t;
    static const int twins[] = {2, 3, 0, 1}, peers[] = {1, 0, 3, 2};

    g_argv = av;

    D("starting %s", av[0]);
    memset(f, 0, sizeof(*f));

    t = f->td;
    f->n_chains = 1; /* unidirectional */
    f->qlen = 1<<18;	/* 16M */
    f->mode = 3;
    f->obj_size = 0;
    t[0].pkt_len = 1500;

    /* getopt etc */
    while ( (ch = getopt(ac, av, "c:l:m:q:v2")) != -1) {
	switch (ch) {
	default:
	    usage();
	    break;
	case 'c': /* base_core */
	    f->base_core = strtol(optarg, NULL, 0);
	    break;
	case 'l': /* pkt_len */
	    t[0].pkt_len = strtol(optarg, NULL, 0);
	    break;
	case 'm': /* mode */
	    f->mode = strtol(optarg, NULL, 0);
	    if (f->mode == 0) {
		f->obj_size = PCQ_OBJ_PTR;
	    } else if (f->mode >= 1 && f->mode <= 3) {
		f->obj_size = 0; // mmap
	    } else {
		D("invalid mode %d, must be 0..3", f->mode);
		usage();
	    }
	    break;
	case 'q': /* qlen */
	    f->qlen = strtol(optarg, NULL, 0);
	    break;
	case '2': /* bidirectional */
	    f->n_chains = 2;
	    break;
	case 'v': /* verbose */
	    f->verbose++;
	    break;
	}
    }
    ac -= optind;
    av += optind;
    if (ac != 2)
	usage();

    for (i = 0; i < 4; i++) {
	t[i].id = i;
	t[i].parent = f;
	t[i].twin = &t[twins[i]];
	t[i].peer = &t[peers[i]];
    }
    for (i = 0; i < 2; i++) {
	struct _sp *x = h;
	for (x = h; x->prefix != NULL; x++) {
	    if (!strncmp(av[i], x->prefix, strlen(x->prefix)) )
		break;
	}
	if (x->prefix == NULL) {
	    usage();
	}
	t[i].handler = t[i].twin->handler = x->handler;
	f->port[i].name = av[i];
    }

    t[1].pkt_len = t[2].pkt_len = t[3].pkt_len = t[0].pkt_len;

    for (i = 0; i < f->n_chains; i++) { /* create one queue per chain */
	t[2*i].q = t[2*i+1].q = f->q[i] = pcq_new(f->qlen, f->obj_size);
    }
    for (i = 0; i < 2*f->n_chains; i++) { /* create one thread per endpoint */
	t[i].core = f->base_core + i;
	pthread_create(&t[i].td_id, NULL, t[i].handler, t+i);
    }

    D("waiting for input to terminate");
    for (;;) {
	int waiting = 0;
	usleep(1000000);
	for (i = 0; i < 2*f->n_chains; i++) {
	    if (t[i].ready == 1) t[i].pr_stat(&t[i]);
	    if (t[i].ready == 2) {
		D("JOIN thread %d, %s", i, t[i].name);
		pthread_join(t[i].td_id, NULL);
                t[i].ready = 3;
            }
	    if (t[i].ready != 3) waiting++;
	}
	if (waiting == 0) break;
    }

    D("all done");
    return 0;
}
