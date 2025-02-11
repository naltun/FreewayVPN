BIN = test_wg
CC = cc
CFLAGS = -Wall -Werror -I../include/
LDFLAGS =
OBJS = test_wg.o ../src/wireguard.o

all: $(BIN)

$(PROG): $(OBJS)
	$(CC) -o $(BIN) $(OBJS) $(LDFLAGS)

test_wg.o: test_wg.c
	$(CC) $(CFLAGS) -c test_wg.c

../src/wireguard.o: ../src/wireguard.c
	$(CC) $(CFLAGS) -c ../src/wireguard.c -o ../src/wireguard.o

clean:
	rm -f $(BIN) $(OBJS)
