PROGS += nm2tcp

CFLAGS = -O3 -pipe -I ../../sys
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -Wextra

LDLIBS += -lpthread
ifeq ($(shell uname),Linux)
        LDLIBS += -lrt  # on linux
endif

SRCS= nm2tcp.c nm_sess.c
OBJS= $(SRCS:%.c=%.o)
CLEANFILES = $(PROGS) $(OBJS)

LDFLAGS += $(LDLIBS)

all: $(PROGS)

nm2tcp.o: nm2tcp.h
nm_sess.o: nm2tcp.h

nm2tcp: nm2tcp.o nm_sess.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	-@rm -rf $(CLEANFILES)
