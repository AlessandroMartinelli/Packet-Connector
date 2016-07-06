PROGS += pconn

CFLAGS = -O3 -pipe -I ../../sys
#CFLAGS += -Werror 
CFLAGS += -Wall -Wunused-function
CFLAGS += -Wextra
CFLAGS += -DDO_STAT
LDLIBS += -lpthread
ifeq ($(shell uname),Linux)
        LDLIBS += -lrt  # on linux
endif

SRCS= pconn.c sess.c #  pconn_tcp.c pconn_netmap.c
OBJS= $(SRCS:%.c=%.o)
CLEANFILES = $(PROGS) $(OBJS) 
BUILDFLDR = build/

LDFLAGS += $(LDLIBS)

all: $(PROGS)
	test -d $(BUILDFLDR) || mkdir $(BUILDFLDR)
	mv -t $(BUILDFLDR) $(CLEANFILES) 

pconn.o: pconn.h pcq.h
sess.o: pconn.h

pconn: pconn.o sess.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	-@rm -rf $(BUILDFLDR)