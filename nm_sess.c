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
 * Session handler to run and network communication
 * over a TCP socket, and also run the callbacks.
 */

#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <arpa/inet.h> // inet_aton
#include <netinet/in.h>
#include <netinet/tcp.h>	// TCP_NODELAY
//#include <sys/cpuset.h> // freebsd, used in rmlock
#include <sys/errno.h>
extern int errno;

#include "nm2tcp.h"

#include <stdio.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/time.h>	/* timersub */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>	/* read() */

#define SOCK_QLEN 5     /* listen lenght for incoming connection */

uint32_t
safe_write(int fd, const char *buf, uint32_t l)
{
	uint32_t i = 0;
	int n = 0;
	for (i = 0; i < l; i += n) {
		n = write(fd, buf + i, l - i);
		if (n <= 0) {
			D("short write");
			break;
		}
	}
	ND(1,"done, i %d l %d n %d", i, l, n);
	return i;
}


int
is_connected(int fd)
{
	struct sockaddr_in sa;
	socklen_t l = sizeof(sa);
        return getpeername(fd, (struct sockaddr *)&sa, &l) == 0 ? 1 : 0;
}

/*
 * 
 * return the listen fd or -1 on error.
 */
int
do_socket(const char *_addr, int nonblock, int *client)
{
    int _cli, fd = -1, on, ret, theport;
    struct sockaddr_in s;
    char *addr, *port;

    /* fill the sockaddr struct */
    bzero(&s, sizeof(s));
    s.sin_family = AF_INET;
    if (client == NULL)
	client = &_cli;
    *client = 1;

    D("start on %s", _addr);
    addr = strdup(_addr);
    if (addr == NULL) {
	D("failed to make a copy of address %s", _addr);
	goto error;
    }
    port = index(addr, ':');
    if (port == NULL) {
	D("missing port number in %s", _addr);
	goto error;
    }
    port[0] = '\0'; /*trick: divide the port from the addr*/
    if (port == addr) {
        /* if port == addr, it means that the addr contains no IP:
         * the mode in this case is: "server" (*client=0) */
	ND("port == addr");
	s.sin_addr.s_addr = INADDR_ANY;
	*client = 0;
    } else {
	if (inet_aton(addr, &s.sin_addr) != 1) {
	    D("inet_aton %s failed", addr);
	    goto error;
	}
	ND("address is %s", inet_ntoa(s.sin_addr));
	*client = (s.sin_addr.s_addr != INADDR_ANY);
    }
    theport = strtol(port+1, NULL, 10); 
    if (theport <= 0 || theport >= 65536) {
	D("invalid port number %d %s", theport, port+1);
	goto error;
    }
    s.sin_port = htons(theport);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
	perror("socket");
	goto error;
    }
    if (nonblock)
	fcntl(fd, F_SETFL, O_NONBLOCK);
on = 1;
#ifdef SO_REUSEADDR
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1)
	perror("SO_REUSEADDR failed(non fatal)");
#endif
#ifdef SO_REUSEPORT
    on = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) == -1)
	perror("SO_REUSEPORT failed(non fatal)");
#endif

    if (*client) {
	ret = connect(fd, (struct sockaddr*) &s, sizeof(s));
	if (ret < 0 && ret != EINPROGRESS) {
	    perror("connect error");
	    goto error;
	}
	ND("+++ connected to tcp %s:%d",
	    inet_ntoa(s.sin_addr), ntohs(s.sin_port));
    } else {
	ret = bind(fd, (struct sockaddr*) &s, sizeof(s));
	if (ret < 0) {
	    perror( "bind" );
	    goto error;
	};
	ND("+++ listening tcp %s:%d",
	    inet_ntoa(s.sin_addr), ntohs(s.sin_port));

	/* listen for incoming connection */
	ret = listen(fd, SOCK_QLEN);
	if (ret < 0) {
	    perror("listen");
	    goto error;
	}
    }
    free(addr);
    D("%s mode on %s", *client ? "client" : "server", _addr);
    return fd;
error:
    if (addr)
	free(addr);
    if (fd != -1)
	close(fd);
    return -1;
}
