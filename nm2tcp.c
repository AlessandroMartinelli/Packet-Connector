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


#define NETMAP_WITH_LIBS
//#include <net/netmap_user.h>

#include "nm2tcp.h"

#if 0 /* description */
This is a genera purpose command that connects two packet streams,
possibly bidirectionally. The streams can be
- netmap
- tcp
- pcap (later)

For each direction, input and output are handled by separate threads,
with a large queue in the middle.

#endif /* description */

#if 0
/*
 * this is a simulated input logger that reads from
 * a random packet generator and pushes to a TCP connection.
 * Assumptions: buflen >= 2 * MY_MAX_PKTLEN
 */
static int
il_body(struct my_il *s)
{
    struct q_pkt_hdr *h;
    uint32_t l, ofs;
    uint64_t i, n, n_bytes, n_pkts, n_writes;

    ofs = 0;
    n = n_bytes = n_pkts = n_writes = 0;
    for (;;) {
	uint32_t pkt_len, reclen;

	if (ofs + MY_MAX_PKTLEN > s->buflen) { /* time to flush */
	    l = safe_write(s->fd, s->buf, ofs);
	    n += l;
	    n_writes++;
	    if (l < ofs) {
		D("middlebox input died ? cycles %lu", (u_long)i);
		goto done;
	    }
	    ofs = 0;
	}

	/* XXX packet input, we assume it can put the packet
	 * at buf[ofs] and specify the packet length
	 */
	pkt_len = 64; // + random() % (1518 - 64); /* eth frame */

	/* total record length including header and padding */
	reclen = q_pad(sizeof(*h) + pkt_len);
	h = (struct q_pkt_hdr *)(s->buf + ofs);
	h->seq = i; /* sequence number */
	h->type = H_TY_DATA; /* data */
	h->len = pkt_len;
	n_pkts++;
	n_bytes += pkt_len;
	ofs += reclen;
    } /* end of read loop */
    /* we always have leftover data */
    l = safe_write(s->fd, s->buf, ofs);
    n += l;
    n_writes++;
done:
    close(s->fd);
    D("done, sent %ld bytes %ld bytes, %d pkts %d writes",
		(long)(n), (long)(n_bytes), (int)n_pkts, (int)n_writes);
    return 0;
}

static int
ol_body(struct my_ol *s)
{
    uint32_t rd, wr;
    uint64_t pkt_count = 0, pal_count = 0, rxbytes = 0;

    rd = wr = 0;
    while (s->fd >= 0 || wr > rd) {
	if (s->fd >= 0) {
	    int nread = read(s->fd, s->buf + wr, s->buflen - wr);
	    RD(1,"read %d at %d", nread, wr);
	    if (nread <= 0) {
		D("middlebox -> ol dead after %ld pkts %ld pals", (long)pkt_count, (long)pal_count);
		close(s->fd);
		s->fd = -1;
	    } else {
		rxbytes += nread;
		wr += nread;
	    }
	}
	/* consume PALs and data packets. */
	for (;;) {
	    uint32_t l;
            struct q_pkt_hdr *h = (struct q_pkt_hdr *)(s->buf + rd);

	    if (wr - rd <= sizeof(*h))
		break; // no header
	    l = q_pad(sizeof(*h) + h->len);
	    if (wr - rd < l)
                break; /* not enough data */
            switch (h->type) {
	    case H_TY_DATA:
		ND(1,"packet %d len %d", h->seq, h->len);
		pkt_count++;
		break;
	    case H_TY_WRAP:
		break;
	    default:
		D("*** unknown chunk %d seq %d len %d", h->type, h->seq, h->len);
		break;
	    }
	    rd += q_pad(sizeof(*h) + h->len);
	}
	if (s->buflen - rd < MY_MAX_PKTLEN) {
            ND(5, "copy up %d from %d", wr - rd, rd);
            if (wr != rd)
                memcpy(s->buf, s->buf + rd, wr - rd);
            wr = wr - rd;
            rd = 0;
        }
    }
}
#endif

static void
usage(void)
{
    D("\n\tusage: nm2tcp [-v] [-2] port1 port2\n"
        "\tports can be netmap:*, vale* or tcp:host:port\n"
        "\thost and port are resolved with the resolver");
    exit(1);
}

/*
 * Helper functions to write on a shared queue.
 * Producer advances tail, consumer advances head.
 */
static inline void PROD_HEAD_UPDATE(struct pkt_q *q)
{
    q->prod_head_update++;
    q->prod_head = q->q_head;
}

static inline void PROD_TAIL_PUBLISH(struct pkt_q *q)
{
    q->prod_tail_update++;
    q->q_tail = q->prod_tail;
}

static inline void CONS_HEAD_PUBLISH(struct pkt_q *q)
{
    q->cons_head_update++;
    q->q_head = q->cons_wr_head;
}

static inline void CONS_TAIL_UPDATE(struct pkt_q *q)
{
    q->cons_tail_update++;
    q->cons_tail = q->q_tail;
}

/*
 * q_write_space() is non blocking,
 * returns the amount of contiguous space for writing in the queue,
 * using cached pointers. Two cases (underscore is free space)
 *   A:    [..t____h..........] 
 *   B:    [_______h.....t____] 
 *
 * q_want_space() is blocking and waits until the desired space
 * is available.
 */
static uint32_t
q_write_space(struct pkt_q *q)
{
    uint32_t s;
    s = q->prod_head > q->prod_tail ?
	q->prod_head - q->prod_tail : q->buflen - q->prod_tail;
    ND(1, "space at %d is %d", q->prod_tail, s);
    return s;
}

/*
 * q_want_space() is BLOCKING and waits until there are at least 'want'
 * bytes for writing into the queue. Wait is done through short usleep()
 */
static uint32_t
q_want_space(struct pkt_q *q, u_int want)
{
    uint32_t l;

    l = q_write_space(q); /* first use cached values */
    if (l >= want)
	return l;

    PROD_HEAD_UPDATE(q); /* update head and retry */
    l = q_write_space(q);
    if (l >= want)
	return l;

    /* Make sure there is enough room to write a contiguous packet. */
    if (q->buflen - q->prod_tail < want) {
	/*
	 * Not enough space at the end of the buffer. Must write a WRAP
	 * command, which resets the tail pointer to 0, but only if the
	 * consumer has head > 0 (and not head > tail, which could happen
	 * if it is almost one lap behind).
	 * IMPORTANT: publish prod_tail to avoid potential deadlocks.
	 * Write updates are not expensive.
	 */
        struct q_pkt_hdr *h = (struct q_pkt_hdr *)(q->buf + q->prod_tail);
	int sleep = 0;

	PROD_TAIL_PUBLISH(q);
	while (q->prod_head > q->prod_tail || q->prod_head == 0) {
	    /* cannot wrap */
	    if (sleep) {
		ND(1, "sleeping q %s prod head %d %s tail %d",
		    q->name, q->prod_head, h_type(q->buf + q->prod_head),
		    q->prod_tail);
		usleep(1);
	    }
	    PROD_HEAD_UPDATE(q);
	    sleep = 1;
	}
	ND("writing wrap command at %d, head at %d",
		q->prod_tail, q->prod_head);
        *h = (struct q_pkt_hdr){ 0, H_TY_WRAP, 0};
	/* q_end records where data actually end.
	 * This can be used to push out packets from the
	 * output vector.
	 */
	q->q_end = q->prod_tail + q_pad(sizeof(*h));
	q->prod_tail = 0;
	PROD_TAIL_PUBLISH(q);
    }

    /* now cycle until we have space */
    while ((l = q_write_space(q)) < want) {
	ND(1, "wait for consumer to make room at %d", q->prod_tail);
	usleep(1);
	PROD_HEAD_UPDATE(q);
    }
    return l;
}


static void
td_wait_ready(struct nmstate *f)
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
    struct nmthread *t = _f;
    struct nmstate *f = t->parent;

    if (t->id < 2) { /* first and second do the open part */
	//t->nm_desc = nm_open(f->port_name[f->id], NULL, 0, NULL);
	if (f->n_chains == 2) {
	    t[2].id = t->id + 2;
	    pthread_create(&t[2].td_id, NULL, t[2].handler, t+2);
	}
    }
    D("thread %p terminating", t);
    return NULL;
}


static void *
f_tcp_read(struct nmthread *t)
{
    uint32_t rd = 0, wr = 0; /* read and write pointers in the buffer */

    D("+++ start reading from input tcp, id %d q %p ready %d", t->id, t->q->buf, t->ready);
    for (; t->ready || wr > rd;) {
        if (t->ready && t->tcp_buflen > wr) {
	    int nread = read(t->fd, t->tcp_buf + wr, t->tcp_buflen - wr);
	    RD(1, "NNN read %d bytes, rd %d wr %d buflen %d",
		nread, rd, wr, t->tcp_buflen);
	    if (nread > 0) {
		wr += nread;
	    } else { /* circuit dead, finish */
		D("WWW closing fd, rd %d wr %d", rd, wr);
		close(t->fd);
		t->fd = -1;
		t->twin->fd = -1;
		t->ready = 0;
		t->twin->ready = 0;
	    }
	}
	ND("/* consume data as long as we have at least one packet */");
	for (;;) {
	    uint32_t x, l;
	    struct q_pkt_hdr *h = (struct q_pkt_hdr *)(t->tcp_buf + rd);
	    struct q_pkt_hdr *hdst;
	    struct pkt_q *q = t->q;

	    if (wr - rd <= sizeof(*h))
		break; /* no header */
	    l = q_pad(sizeof(*h) + h->len);
	    if (wr - rd < l)
		break; /* not enough data */
	    ND(1, "at %d pkt seq %d ty %d len %d reclen %d head %d tail %d",
		rd, (int)h->seq, h->type, h->len, l, q->q_head, q->q_tail);
	    t->pkt_count++;
	    t->byte_count += h->len;

	    /* need space for packet and wrap command */
	    x = q_want_space(q, l + sizeof(*h));
	    (void)x;
	    hdst = (struct q_pkt_hdr *)(q->buf + q->prod_tail);
	    q->prod_pkts++;
	    memcpy(hdst, h, l); /* copy packet */
	    ND(1, "sending packet at %d space %d len %d %d ty %d",
		    q->prod_tail, x, l, hdst->len, hdst->type);
	    q->prod_tail += l;
	    if (q->prod_tail >= q->buflen) {
		D("------ overflow tail at %ld", (long)q->prod_tail);
	    }

	    rd += l;
	}
	if (!t->ready && wr > rd) {
	    struct q_pkt_hdr *h = (struct q_pkt_hdr *)(t->tcp_buf + rd);
	    D("***** ouch, fd closed and incomplete packet wr %d > rd %d, l %d", wr, rd, h->len);
	    break;
	}
	// publish active tail
	PROD_TAIL_PUBLISH(t->q);

	/*
	 * Here we have consumed up to rd. If we are getting close
	 * to the end of the buffer, copy any leftover data to the
	 * beginning and wrap.
	 */
	if (t->tcp_buflen - rd < MY_MAX_PKTLEN) {
	    ND(5, "copy up %d from %d", wr - rd, rd);
	    if (wr != rd)
		memcpy(t->tcp_buf, t->tcp_buf + rd, wr - rd);
	    wr = wr - rd;
	    rd = 0;
	}
	RD(1, "... got %d Mbytes", (int)(t->byte_count/1000000));
    }
    RD(1, "--- Finished, received %ld bytes", (long)(t->byte_count));

    {
        struct pkt_q *q = t->q;
	struct q_pkt_hdr *h = (struct q_pkt_hdr *)(q->buf + q->prod_tail);
	D("--- send CLOSE to %s tail %d", q->name, q->prod_tail);
	*h = (struct q_pkt_hdr){ 0, H_TY_CLOSE, 0};
	q->prod_tail += q_pad(sizeof(*h));
	PROD_TAIL_PUBLISH(q);
    }
    return NULL;
}


#if 0
/*
 * build blocks for PALs in the output buffer.
 * XXX for the time being, just do small writes
 */
static void
q_pkt_push(struct nmthread *fo, uint32_t id, char *src, uint32_t len)
{
    /* construct a template PAL */
    struct q_pkt_hdr h = { id, H_TY_PAL, 0 };
    static const char pad[Q_ALIGN];
    uint32_t x, l, ofs;

    ND(4, "fo %p buf %p len %d", fo, src, len);
    // XXX watch out for padding here
    for (ofs = 0; ofs < len; ) {
	x = (len < 32768) ? len : 32768;
	h.len = x;
	l = safe_write(fo->fd, (const char *)&h, sizeof(h));
	l = safe_write(fo->fd, src + ofs, x);
	(void)l; // XXX silence compiler
	ofs += x;
	x = q_pad(x) - x; /* padding size */
	if (x)
	    l = safe_write(fo->fd, pad, x);
    }
}
#endif


/*
 * ---------------- OUTPUT LOGGER FOR MIDDLEBOX ----------
 * read from queue, push to tcp
 */
static void *
f_tcp_write(struct nmthread *t)
{
    struct pkt_q *q = t->q;

    D("III start thread %d buf %p", t->id, q->buf);
    for (;;)  {
	/* fetch the queue pointers. tail is changed by the other endpoint */
	uint32_t x, l, tail = q->q_tail, head = q->q_head;
	int idle = (tail == head);
        struct q_pkt_hdr *h = (struct q_pkt_hdr *)(q->buf + head);

	if (!t->ready && idle) {
	    D("*** terminating, idle %d", idle);
	    break;
	}
	if (idle) {
	    usleep(100);
	    continue;
	}
	ND(5, "head %lu tail %lu", (u_long)head, (u_long)tail);
	if (head > tail) {
	    x = q->q_end - head;
	    head = 0;
	} else {
	    x = tail - head;
	    head = tail;
	}
	if (x > 0) {
	    ND(5, "write %d bytes len %d ty %d", x, h->len, h->type);
	    l = safe_write(t->fd, (const char *)h, x);
	    if (l != x) { // short write
	        RD(5, "short write want %d have %d", x, l);
		break;
	    }
	    q->q_head = head; /* report progress */
	}
    }
    D("thread b terminating");
    return NULL;
}

#if 0
/*
 * push a packet to a output queue
 */
static void
outq_push(struct pkt_q *q, struct q_pkt_hdr *h)
{
    uint32_t l = q_pad(sizeof(struct q_pkt_hdr) + h->len);

    q_want_space(q, l + sizeof(*h));
    memcpy(q->buf + q->prod_tail, h, l);
    q->prod_tail += l;
    PROD_TAIL_PUBLISH(q);
}
#endif

struct q_pkt_hdr * q_get_pkt(struct pkt_q *in_q);
void q_put_pkt(struct pkt_q *in_q, int how);
int q_close(struct pkt_q *in_q);

/*
 * non blocking call, returns the next packet
 * using q->cons_head as the read pointer.
 * q->cons_wr_head is not updated.
 * We might find a WRAP in front of the packet, so skip it
 */
struct q_pkt_hdr *
q_get_pkt(struct pkt_q *in_q)
{
    struct q_pkt_hdr *h;

again:
    if (in_q->cons_head == in_q->cons_tail) {
	CONS_TAIL_UPDATE(in_q); /* any new data from producer ? */
	if (in_q->cons_head == in_q->cons_tail) {
	    ND(1, "at %ld blocked cons_head %ld cons_wr_head %ld q_head %ld q_tail %ld buflen %ld",
		(long)in_q->cons_pkts,
		(long)in_q->cons_head, (long)in_q->cons_wr_head,
		(long)in_q->q_head, (long)in_q->q_tail, (long)in_q->buflen);
	    return NULL;
	}
    }
    h = (struct q_pkt_hdr *)(in_q->buf + in_q->cons_head);
    if (h->type != H_TY_DATA) { /* wrap command ? */
	if (h->type == H_TY_CLOSE) {/* no more data */
	    RD(1, "--- %s received TY_CLOSE", in_q->name);
	    return NULL;
	}
	ND(1, "wrap %d -> %d (tail is %d)",
	    in_q->cons_head, 0, in_q->cons_tail);
	in_q->cons_head = 0;
	goto again;
    }
    ND("pkt %d len %d at %d", h->seq, h->len, in_q->cons_head);
    ND(1, "got pkt at %d", in_q->cons_head);
    in_q->cons_pkts++;
    in_q->cons_head += q_pad(sizeof(*h) + h->len);
    if (in_q->cons_head >= in_q->buflen)
	    D("---- overflow head %ld",
		(long)in_q->cons_head);
    return h;
}

/* advance the head pointer on the queue.
 * The second argument tells how to advance it (one packet or all
 * pending ones).
 * The actual head is only advanced if short of space.
 * We might find a WRAP before the packet, but never try to skip
 * after the packet or we should check q_tail.
 */
void
q_put_pkt(struct pkt_q *in_q, int how)
{
    if (how == 0) { /* one packet */
	struct q_pkt_hdr *h;
	uint32_t next;

        h = (struct q_pkt_hdr *)(in_q->buf + in_q->cons_wr_head);
	if (h->type == H_TY_WRAP) { /* wrap command ? */
	    ND("+++ wrap at %d", (int)in_q->cons_wr_head);
	    in_q->cons_wr_head = 0;
            h = (struct q_pkt_hdr *)(in_q->buf + in_q->cons_wr_head);
	}
	next = in_q->cons_wr_head + q_pad(sizeof(*h) + h->len);
	if (next >= in_q->buflen) {
	    D("---- update head cons_head %ld cons_wr_head %ld -> %ld ty %d",
		(long)in_q->cons_head,
		(long)in_q->cons_wr_head, (long)next, h->type);
	}
	in_q->cons_wr_head = next;
    } else { /* all packets */
	in_q->cons_wr_head = in_q->cons_head;
    }
    /* XXX invariant, on entry cons_head == cons_wr_head */
    if (in_q->cons_head != in_q->cons_wr_head)
	RD(1, "--- at %ld invalid head %ld wr_head %ld",
	    (long)in_q->cons_pkts,
	    (long)in_q->cons_head, (long)in_q->cons_wr_head);

    /* XXX force publish. It is complicated to optimize this because
     * there is uncertainty on the WRAP packet.
     * If we really want, we should publish when we are at cons_tail
     * or stopped on a WRAP entry.
     */
    CONS_HEAD_PUBLISH(in_q);
}

int
q_close(struct pkt_q *q)
{
    struct q_pkt_hdr *h = (struct q_pkt_hdr *)(q->buf + q->cons_wr_head);
    return (h->type == H_TY_CLOSE);
}

static void *
f_tcp_body(void *_f) /* read */
{
    struct nmthread *t = _f;
    struct nmstate *f = t->parent;
    void *(*cb)(struct nmthread *) = (t->id == 0 || t->id == 3) ? f_tcp_read : f_tcp_write;

    D("start thread %d", t->id);
    /* complete initialization */
    t->pkt_count = t->byte_count = 0;
    t->tcp_buflen = MY_TCP_BUFLEN;
    t->tcp_buf = SAFE_CALLOC(t->tcp_buflen);
    if (t->id < 2) { /* first and second do the open part */
        int client = 1;
	t->listen_fd = -1;
	t->fd = do_socket(f->port_name[t->id] + 4, 0, &client); // client
	if (t->fd < 0) {
	    D("*** cannot to %s", f->port_name[t->id]);
	    return NULL;
	}
	ND("mode for %d is %s", t->id, client ? "client" : "server");
	if (!client) {
	    t->listen_fd = t->fd;
	    t->fd = -1;
	}
	t->ready = 1;
	if (f->n_chains == 2) {
	    t[2].fd = t->fd;
	    t[2].listen_fd = t->listen_fd;
	    pthread_create(&t[2].td_id, NULL, t[0].handler, t+2);
	}
    }

    td_wait_ready(t->parent); /* wait for client threads to be ready */
    if (t->listen_fd == -1) { /* client mode, connect and done */
	D("-- running %d in client mode", t->id);
	cb(t);
    } else { /* server mode, base does accept, twin waits for fd */
    	for (;;) {
	    D("III running %d in server mode on fd %d", t->id, t->listen_fd);
	    t->fd = t->id < 2 ? accept(t->listen_fd, NULL, 0) : t->twin->fd;
	    if (t->fd < 0) {
		D("accept failed, retry");
		sleep(1);
	    } else {
		D("accept for %d successful, start", t->id);
		t->ready = t->twin->ready = 1;
		cb(t);
	    }
	    D("III closing %d in server mode", t->id);
	}
    }
    if (t->id < 2 && f->n_chains == 2) {
        pthread_join(t[2].td_id, NULL);
    }
    return NULL;
}

/*
 * main program: setup initial parameters and threads, run
 */
int
main(int ac, char **av)
{
    struct nmstate _f, *f = &_f;
    uint32_t i;
    int ch;
    struct nmthread *t;
    static const int twins[] = {2, 3, 0, 1}, peers[] = {1, 0, 3, 2};

    D("starting %s", av[0]);
    memset(f, 0, sizeof(*f));

    t = f->td;
    f->n_chains = 1; /* unidirectional */
    /* getopt etc */
    while ( (ch = getopt(ac, av, "v2")) != -1) {
	switch (ch) {
	default:
	    usage();
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

    t[0].q = t[1].q = &f->q[0];
    t[2].q = t[3].q = &f->q[1];
    for (i = 0; i < 4; i++) {
	t[i].id = i;
	t[i].parent = f;
	t[i].twin = &t[twins[i]];
	t[i].peer = &t[peers[i]];
    }
    for (i = 0; i < 2; i++) {
	if (!strncmp(av[i], "netmap:", 6) || !strncmp(av[i], "vale", 4)) {
	    t[i].handler = f_netmap_body;
	} else if (!strncmp(av[i], "tcp:", 4)) {
	    t[i].handler = f_tcp_body;
	} else {
	    usage();
	}
	f->port_name[i] = av[i];
    }

    for (i = 0; i < f->n_chains; i++) {
	f->q[i].buflen = MY_Q_BUFLEN;
	f->q[i].buf = SAFE_CALLOC(f->q[i].buflen);
	sprintf(f->q[i].name, "qn[%d]", i);
    }
    for (i = 0; i < 2; i++) {
	pthread_create(&t[i].td_id, NULL, t[i].handler, t+i);
    }

    D("waiting for input to terminate");
    for (i = 0; i < 2*f->n_chains; i++) {
        pthread_join(t[i].td_id, NULL);
	t[i].ready = 0;
    }

    D("all done");
    return 0;
}
