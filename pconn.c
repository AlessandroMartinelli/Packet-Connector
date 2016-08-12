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

void print_bytes(unsigned char* buf, int len){
	int i;
	for(i=0;i<len-1;i++)
		printf("%02X:",buf[i]);
	printf("%02X\n",buf[len-1]);
}

static void *
f_test_stats(void *_f)
{
    struct my_td *t = _f;
    struct test_t *d = t->data;
    uint64_t now = ts64();
    double dt = (now - d->ts)/1e9;

#define X(v) (u_long)(d->q->v - d->dumpq.v)
    D("T%d %.3f s %.3e tps %.3e Bps pctr: %llu; %lu %lu %lu %lu %lu - %lu %lu %lu %lu %lu %lu",
		t->id,
		dt, (double)(d->pctr - d->pctr_old)/dt,
		(double)(d->bctr - d->bctr_old)/dt,
                d->pctr,
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
    D("\n\n\tUSAGE: %s [-c BASE_CORE] [-l PKT_LEN] [-m MODE] [-q Q_LEN] [-v] [-2]"
            " port1 port2\n"
        "\t * port can be netmap:*, vale*, pcap:device or tcp:host:port\n"
        "\t * host and port are resolved with the resolver", g_argv[0]);
    exit(1);
}


static void
td_wait_ready(struct pconn_state *f)
{
    uint32_t i;

    /* wait for first two threads to be ready */
    for (i = 0; i < f->n_chains; ) {
	if (!f->td[i].ready) { /* TODO_ST: if(f->t[i].state == NOT_READY)*/
	    D("thread %d not ready, wait...", i);
	    usleep(1000);
	    continue; /* loop without i++ */
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

/* Before we can provide an example of using pcap_loop(), we must examine the 
 * format of our callback function. We cannot arbitrarily define our callback's 
 * prototype; otherwise, pcap_loop() would not know how to use the function.
 * So we use this format as the prototype for our callback function:

	void got_packet(u_char *args, const struct pcap_pkthdr *header,
	    const u_char *packet);
 * Let's examine this in more detail. First, you'll notice that the function has
 * a void return type. This is logical, because pcap_loop() wouldn't know how to
 * handle a return value anyway. The first argument corresponds to the last
 * argument of pcap_loop(). Whatever value is passed as the last argument to 
 * pcap_loop() is passed to the first argument of our callback function every 
 * time the function is called. The second argument is the pcap header, which 
 * contains information about when the packet was sniffed, how large it is, etc.
 * The pcap_pkthdr structure is defined in pcap.h as:

	struct pcap_pkthdr {
		struct timeval ts; // time stamp 
		bpf_u_int32 caplen; // length of portion present /
		bpf_u_int32 len; // length this packet (off wire) 
	};

*/

/**************** callback methods for f_generalized_write() ****************/
/* NOTE: all return negative value in case of error, except finalize        */

int pcap_packet_inject(struct my_td *t, char* buf, int len){
    struct pcap_pkthdr header;
    struct timeval now;
    int ret;
    
    if(t->pcap_dumper){
        /* offline mode */
        gettimeofday(&now, NULL);
        header = (struct pcap_pkthdr){now, len, len};
        pcap_dump((u_char*)t->pcap_dumper, &header, (u_char*)buf);
        return 1;
    } else {
        /* online mode */
        
        /* if packet is greater than MTU ignore it */
        /* TODO_ST: this is a problem: in fact the pcap_inject cannot handle packets
         * bigger than MTU, apparently
         */
        if (len > 1514) {
            D("Captured packet size: %d; ignoring it", len);
            return 1;
        }
        ret = pcap_inject(t->pcap_fd, buf, len);
        if(ret < 0){
            D("Thread %d: Inject returned %d: pcap error: %s",t->id, ret, pcap_geterr(t->pcap_fd));
        }
        return ret;
    }
}

int tcp_packet_inject(struct my_td *t, char* buf, int len){
    (void)t;
    (void)buf;
    (void)len;
    
    return 0;
}

int pcap_data_inject(struct my_td *t, char* buf, int len){
    (void)t;
    (void)buf;
    (void)len;
    
    return 0;
}

int tcp_data_inject(struct my_td *t, char* buf, int len){
    int cur;
    cur = safe_write(t->fd, buf, len);
    if (cur != len) { // short write, circuit closed
        RD(5, "short write want %d have %d", len, cur);
        return -1;
    }
    return 0;
}

void tcp_finalize(struct my_td *t){
    D("WWW (thread %d) closing fd",t->id);
    close(t->fd);
    t->fd = t->twin->fd = -1;
}

void pcap_finalize(struct my_td *t){
    D("WWW (thread %d) closing pcap_fd",t->id);
    //threads 0 and 1 close the pcap stream
    if(t->pcap_dumper) {
        pcap_dump_close(t->pcap_dumper);
    }
    if(t->id == 0 || t->id == 1){
        D("closing pcap_fd: %p", t->pcap_fd);
        pcap_close(t->pcap_fd);
    }
}

/****************************************************************************/


/* Callback to read from an interface with pcap
 */
void f_pcap_read(u_char *arg, const struct pcap_pkthdr *header,
	    const u_char *packet){
    struct my_td *t = (struct my_td*) arg;
    struct pcq_t *q = t->q;
    int need;
    if(t->ready != 1){
        pcap_breakloop(t->pcap_fd);
        
        D("WWW closing fd, local %d", q->prod_pi);
        /*pcap_close(t->pcap_fd); //TODO_ST: handle critical run.. maybe semaphores?
        t->pcap_fd = t->twin->pcap_fd = NULL; //same side */
        pcap_finalize(t);
        return;
    }

    char *buf = (char *)(q->store);
    struct test_t *d = t->data;   
    //int avail;  //TODO_ST: is it useful? not used at the moment.
    struct q_pkt_hdr *h; /* h points to a descriptor at buf + prod_pi */
    
    /*D("header len: %d, header caplen: %d; prod_pi: %d; public_prod_pi; %d", header->len, 
            header->caplen, q->prod_pi, q->__prod_index);*/    //TODO_ST: len or caplen? correct also lines 210-211
    
    need = q_pad(sizeof(*h) + header->caplen);
    /*avail = */pcq_wait_space(q, need);
    h = (struct q_pkt_hdr *)(buf + pcq_ofs(q, q->prod_pi));
    *h = (struct q_pkt_hdr){ d->pctr, H_TY_DATA, header->caplen};
    memcpy(h+1, packet, header->caplen);
    
    /*printf("\n---------------\n (producer, seq#: %d, padding size: %d %d)",d->pctr, need, sizeof(*h) + header->caplen);
    print_bytes((unsigned char*)(buf + pcq_ofs(q, q->prod_pi)), header->caplen + sizeof(*h));*/
    
    d->bctr += need;
    d->pctr += 1;
    
    pcq_prod_advance(q, need, true);
}

/* This function read data from the queue and write onto a specific device
 * through the use of 3 different callbacks, that could be customized depending
 * on the interface we are using.
 */
static void *
f_generalized_write(struct my_td *t) {
    struct pcq_t *q = t->q;
    char *buf = (char *) (q->store);
    struct test_t *d = t->data;
    int ret;

    while (t->ready == 1) {
        struct q_pkt_hdr *h;
        index_t need, avail, cur = q->cons_ci;

        /* Fetch one packet from the queue. Eventually we'll get it */
        avail = pcq_wait_data(q, sizeof (*h));
        h = (struct q_pkt_hdr *) (buf + pcq_ofs(q, cur));
        need = q_pad(sizeof (*h) + h->len);
        if (avail < need)
            avail = pcq_wait_data(q, need);

        ND("start at ofs %x", cur);
        while (true) {
            //send the packet in the interface 
            /*D("WWW - Write to device: (%d bytes) ", h->len);
            print_bytes((unsigned char*) (buf + sizeof(*h) + pcq_ofs(q, cur)), h->len);*/
            ret = t->inject_single_packet(t, buf + sizeof(*h) + pcq_ofs(q, cur), h->len);
            if(ret<0){
                t->ready = 2;   //TODO_ST: is it right to go to state 2?
                break;
            }
            d->pctr += 1;

            // XXX optional check type 
            cur += need;
            avail -= need;
            if (h->type == H_TY_CLOSE) {
                D("--- found close");
                t->ready = 0;
                break;
            }
            /* prepare for next packet, break if not available */
            h = (struct q_pkt_hdr *) (buf + pcq_ofs(q, cur));
            if (avail < sizeof (*h))
                break;
            need = q_pad(sizeof (*h) + h->len);

            if (avail < need) {
                D("ofs %x need %x have %x", cur, need, avail);
                break;
            }
        }
        need = cur - q->cons_ci; /* how many bytes to send */
        if (need == 0) {
            D("thread %d: should not happen, empty block ?", t->id);
            continue;
        }
        
        ret = t->inject_multiple_data(t, buf + pcq_ofs(q, q->cons_ci), need);
        if(ret<0){
            break;
        }
        
        d->bctr += need;
        //d->pctr += 1;//TODO_ST: maybe this increment must be moved into the inner while 
        pcq_cons_advance(q, need); /* lazy notify */
    }
    
    t->inject_finalize(t);
    return NULL;
}

/* Behaviour of pcap threads
 * 1) Open pcap descriptor
 * 2) If in bidirectional mode, pass the descriptor to the twins
 * 3) If producer, use pcap_loop with callback f_pcap_read
 *    TODO_ST: what happens if callback is fired by pcap_loop if an instance of 
 *    f_pcap_read is blocked waiting for available space on the queue?
 * 4) If consumer, use pcap_inject (inside f_pcap_write) to read from the queue
 *    and writing on pcap device.
 *    If producer, use pcap_loop to iteratively push packets into the queue.
 */
static void *
f_pcap_body(void *_f){
#ifndef WITH_PCAP
    (void)_f;
    D("pcap unsupported");
#else
    struct my_td *t = _f;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pconn_state *f = t->parent;
    const char *device;
    char *pcap_out_filename;

    snprintf(t->name, sizeof(t->name) - 1, "%s%d",
	t->id == 0 || t->id == 3 ? "read" : "write", t->id);
    my_td_init(t);

    if (t->q->capacity < 8 * MY_MAX_PKTLEN) {
	D("TERMINATE, queue too short, need at least %d bytes", 8 * MY_MAX_PKTLEN);
	t->ready = t->peer->ready = 2;
	return NULL;
    }
    
    //initializes function pointers
    t->inject_single_packet = pcap_packet_inject;
    t->inject_multiple_data = pcap_data_inject;
    t->inject_finalize = pcap_finalize;
    
    D("start thread %d", t->id);
    /* complete initialization */

    if (t->id < 2) { /* first and second open the pcap connection */
        t->listen_fd = -1;
        device = f->port[t->id].name + 5; /* move beyond "pcap:" */
	
        if (*(device) == '.'){
            D("pcap: opening offline file %s", device+2);
            /* e.g. pcap:./filename.ext */
            t->pcap_fd = pcap_open_offline(device+2, errbuf);
            
            /* Opens a file for dumping read values from the interface.
             * This is done only when in offline mode, so that symmetry between
             * inject and dispatch behaviors is always present (when in offline
             * mode, both inject and dispatch work on files)
             * 
             * "read from" file will have name [filename].pcap, the one choosen as
             * command line argument.
             * "write to" file will have name out_[filename].pcap
             */
            pcap_out_filename = (char*)malloc(strlen(device+2) + 5);
            sprintf(pcap_out_filename, "out_%s", device+2);
            t->pcap_dumper = pcap_dump_open(t->pcap_fd, pcap_out_filename);
            if(t->pcap_dumper == NULL){
                D("Error opening %s for writing", pcap_out_filename);
                t->ready = t->twin->ready = 2;
                free(pcap_out_filename);
                return NULL;
            }
            free(pcap_out_filename);
        } else {
            /* e.g. pcap:eth0 */
            D("pcap: opening live device %s", device);
            t->pcap_fd = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
        }
        
        if (t->pcap_fd == NULL) {
            D("Couldn't open device %s: %s\n", f->port[t->id].name, errbuf);
            t->ready = t->twin->ready = 2;
            return NULL;
        }
	t->ready = 1;
	if (f->n_chains == 2) {
	    t->twin->pcap_fd = t->pcap_fd;
            t->twin->ready = 1;
            pthread_create(&t[2].td_id, NULL, t[0].handler, t+2);
	}
    }

    td_wait_ready(t->parent); /* wait for client threads to be ready */
    if (t->id == 0 || t->id == 3) { /* producer reads packets and pull in queue */
	D("+++ start reading from input pcap, id %d q %p ready %d", t->id, t->q, t->ready);
        /* pcap_loop(), differently from pcap_dispatch(), doesn't return when the
         * packets timeout occurs. pcap_loop() listen forever also if no packets
         * arrive for a long time.
         */
        pcap_loop(t->pcap_fd, -1, f_pcap_read, (u_char*) t);
    } else { /* consumer writes packets into device */
        f_generalized_write(t);
    }
    t->ready = t->twin->ready = 2;
    if (t->id < 2 && f->n_chains == 2) {
        D("Thread %d: JOIN twin thread %d, %s", t->id, t->twin->id, t->twin->name);
        pthread_join(t->twin->td_id, NULL);
    }
    return NULL;
#endif
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
    return NULL;
}


/*
 * read from queue, push to tcp
 */

#if 0
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
    return NULL;
}
#endif

/* Behaviour of tcp threads
 * 1) Only first 2 threads open a socket (shared with twin in bidirectional mode)
 * 2) Distinguish among server/client connection:
 *    - 
 */
static void *
f_tcp_body(void *_f)
{
    struct my_td *t = _f;
    struct pconn_state *f = t->parent;
    void *(*cb)(struct my_td *) = (t->id == 0 || t->id == 3) ? f_tcp_read : f_generalized_write;

    snprintf(t->name, sizeof(t->name) - 1, "%s%d",
	t->id == 0 || t->id == 3 ? "read" : "write", t->id);
    my_td_init(t);

    if (t->q->capacity < 8 * MY_MAX_PKTLEN) {
	D("TERMINATE, queue too short, need at least %d bytes", 8 * MY_MAX_PKTLEN);
	t->ready = t->peer->ready = 2;
	return NULL;
    }
    
    //initializes function pointers
    t->inject_single_packet = tcp_packet_inject;
    t->inject_multiple_data = tcp_data_inject;
    t->inject_finalize = tcp_finalize;
    
    D("start thread %d", t->id);
    /* complete initialization */
    
    if (t->id < 2) { /* first and second open the tcp connection */
        int client = 1;
        t->listen_fd = -1;
	
	t->fd = do_socket(f->port[t->id].name + 4, 0, &client); // client Names start with tcp:
	if (t->fd < 0) {
	    D("*** cannot to %s", f->port[t->id].name);
            t->ready = t->twin->ready = 2;
	    return NULL;
	}
	D("mode for %d is %s", t->id, client ? "client" : "server");
	if (!client) {
	    t->listen_fd = t->fd;
	    t->fd = -1;
	}
	t->ready = 1;
	if (f->n_chains == 2) {
	    t->twin->fd = t->fd;
	    t->twin->listen_fd = t->listen_fd;
            t->twin->ready = 1;
	    pthread_create(&t[2].td_id, NULL, t[0].handler, t+2);
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
            //printf("id=%d, twin fd is %d\n",t->id,t->twin->fd);
	    t->fd = t->id < 2 ? accept(t->listen_fd, NULL, 0) : t->twin->fd;
	    if (t->fd < 0) {
		D("accept failed, retry");
		sleep(1);
	    } else {
		D("accept for %d successful, start", t->id);
		t->ready = t->twin->ready = 1;
		cb(t);
		t->ready = t->twin->ready = 0;
	    }
	    D("III closing %d in server mode", t->id);
	}
    }
    if (t->id < 2 && f->n_chains == 2) {
        D("Thread %d: JOIN twin thread %d, %s", t->id, t->twin->id, t->twin->name);
        pthread_join(t->twin->td_id, NULL);
    }
    return NULL;
}

void generate_arp_frame(char** frame, int* len){
    int fd = -1;
    const char* target_ip_string="1.2.3.4";
    const char* if_name="veth0";
    // Construct Ethernet header (except for source MAC address).
    // (Destination set to broadcast address, FF:FF:FF:FF:FF:FF.)
    struct ether_header header;
    header.ether_type=htons(ETH_P_ARP);
    memset(header.ether_dhost,0xff,sizeof(header.ether_dhost));

    // Construct ARP request (except for MAC and IP addresses).
    struct ether_arp req;
    req.arp_hrd=htons(ARPHRD_ETHER);
    req.arp_pro=htons(ETH_P_IP);
    req.arp_hln=ETHER_ADDR_LEN;
    req.arp_pln=sizeof(in_addr_t);
    req.arp_op=htons(ARPOP_REQUEST);
    memset(&req.arp_tha,0,sizeof(req.arp_tha));

    // Convert target IP address from string, copy into ARP request.
    struct in_addr target_ip_addr={0};
    if (!inet_aton(target_ip_string,&target_ip_addr)) {
       D("ARP generation: %s is not a valid IP address",target_ip_string);
       goto arp_error;
    }
    memcpy(&req.arp_tpa,&target_ip_addr.s_addr,sizeof(req.arp_tpa));

    // Write the interface name to an ifreq structure,
    // for obtaining the source MAC and IP addresses.
    struct ifreq ifr;
    size_t if_name_len=strlen(if_name);
    if (if_name_len<sizeof(ifr.ifr_name)) {
        memcpy(ifr.ifr_name,if_name,if_name_len);
        ifr.ifr_name[if_name_len]=0;
    } else {
        D("ARP generation: interface name is too long");
        goto arp_error;
    }

    // Open an IPv4-family socket for use when calling ioctl.
    fd=socket(AF_INET,SOCK_DGRAM,0);
    if (fd==-1) {
        D("ARP generation: error opening socket");
        goto arp_error;
    }

    // Obtain the source IP address, copy into ARP request
    if (ioctl(fd,SIOCGIFADDR,&ifr)==-1) {
        D("ARP generation: error obtaining IP address");
        goto arp_error;
    }
    struct sockaddr_in* source_ip_addr = (struct sockaddr_in*)&ifr.ifr_addr;
    memcpy(&req.arp_spa,&source_ip_addr->sin_addr.s_addr,sizeof(req.arp_spa));

    // Obtain the source MAC address, copy into Ethernet header and ARP request.
    if (ioctl(fd,SIOCGIFHWADDR,&ifr)==-1) {
        D("ARP generation: error obtaining MAC address");
        goto arp_error;
    }
    if (ifr.ifr_hwaddr.sa_family!=ARPHRD_ETHER) {
        D("ARP generation: not an Ethernet interface");
        goto arp_error;
    }
    const unsigned char* source_mac_addr=(unsigned char*)ifr.ifr_hwaddr.sa_data;
    memcpy(header.ether_shost,source_mac_addr,sizeof(header.ether_shost));
    memcpy(&req.arp_sha,source_mac_addr,sizeof(req.arp_sha));
    close(fd);

    // Combine the Ethernet header and ARP request into a contiguous block.
    *len = sizeof(struct ether_header)+sizeof(struct ether_arp);
    *frame = (char*)calloc(*len, sizeof(char));
    memcpy(*frame,&header,sizeof(struct ether_header));
    memcpy(*frame+sizeof(struct ether_header),&req,sizeof(struct ether_arp));
    return;
    
arp_error:
    *frame = NULL;
    *len = 0;
    if(fd != -1){
        close(fd);
    }
    return;      
}

static void *
f_test_body(void *_f)
{
    struct my_td *t = _f;
    struct pconn_state *f = t->parent;
    struct test_t *d;
    struct pcq_t *q = t->q;
    int mode = f->mode;
    char* arp_frame;
    int arp_len;

    snprintf(t->name, sizeof(t->name) - 1, "%s%d",
	t->id == 0 || t->id == 3 ? "prod" : "cons", t->id);
    my_td_init(t);
    d = t->data;
    
    if(t->id < 2 && f->n_chains == 2) {/*first 2 threads initialize second chain */
        pthread_create(&t[2].td_id, NULL, t[0].handler, t+2);
    }
    
    if(t->id == 0 || t->id == 3){
        /* only the producers must create the arp frame */
        generate_arp_frame(&arp_frame, &arp_len);
        if(arp_frame == NULL){
            D("Error generating ARP frame. Switching to simulated queue filling");
        } else {
            t->pkt_len = arp_len;
        }
        D("frame len = %d bytes",t->pkt_len);
    }
    
    t->ready = 1;
    D("now thread %d ready", t->id);
    /* body */

    D("---- running in mode %d id %d store %p -------", mode, t->id, q->store);
    while (t->ready && d->stop < 100) {
	struct q_pkt_hdr *h;
	char *buf = (char *)(q->store);

	if (t->id == 1 || t->id == 2) { /* consumer */
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
                
                /*printf("\n---------------\n (consumer, seq#: %d)",h->seq);
                print_bytes((unsigned char*)h, sizeof(*h)+h->len);*/
                
		pcq_cons_advance(q, need);
		d->bctr+= h->len;
		break;
	    }
	} else { /* producer */
	    index_t want/*, avail*/;
	    h = (struct q_pkt_hdr *)(buf + pcq_ofs(q, q->prod_pi));

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
		/*avail = */pcq_wait_space(d->q, want);
		ND("write at %p", h);
		*h = (struct q_pkt_hdr){ d->pctr, H_TY_DATA, t->pkt_len};
                
                if(arp_frame!=NULL){
                    memcpy(h+1,arp_frame,t->pkt_len);
                }
                /*D("RRR - write data to queue (%d bytes): ",t->pkt_len);
                print_bytes((unsigned char*)(h+1),t->pkt_len);*/
		//memset(h+1, 'z', t->pkt_len);
		d->bctr += h->len;
		pcq_prod_advance(q, want, (d->pctr & 0xff) != 0);
		break;
	    }
	}
	d->pctr++;
    }
done:
    /* exiting */
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
        {"pcap:", f_pcap_body},
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
    for (i = 0; i < 2; i++) { /* create one thread per endpoint */
	t[i].core = f->base_core + i;
	pthread_create(&t[i].td_id, NULL, t[i].handler, t+i);
    }

    D("waiting for input to terminate");
    for (;;) {
	int waiting = 0;
	usleep(1000000);
	for (i = 0; i < 2*f->n_chains; i++) {
            /* TODO_ST: switc(t[i].ready){} */
	    if (t[i].ready == 1) { /* ready */
                t[i].pr_stat(&t[i]);
            }
	    if (t[i].ready == 2) { /* complete */
		D("Thread main: JOIN thread %d, %s", i, t[i].name);
		pthread_join(t[i].td_id, NULL);
                t[i].ready = 3;
            }
	    if (t[i].ready != 3) { /* not ready */
                waiting++;
            }
	}
	if (waiting == 0) break;
    }

    D("all done");
    return 0;
}
