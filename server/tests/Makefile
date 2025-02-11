BIN = test_wg
CC = cc
CFLAGS = -Wall -Werror -I../include/
LDFLAGS =
OBJS = test_wg.o wireguard.o

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) -o $(PROG) $(OBJS) $(LDFLAGS)

clean:
	rm $(PROG) $(OBJS)
