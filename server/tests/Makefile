BIN = test_wg
CC = cc
CFLAGS = -Wall -Werror -I../include/
OBJS = test_wg.o ../src/wireguard.o

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) -o $@ $(OBJS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(BIN) $(OBJS)
