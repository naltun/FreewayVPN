BIN = test_wg
CC = cc
CFLAGS = -Wall -Werror -I../include/ -I/usr/local/include
LDFLAGS = -L/usr/local/lib -lsodium
OBJS = test_wg.o ../src/wireguard.o ../src/base64/b64_ntop.o ../src/base64/b64_pton.o

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(BIN) $(OBJS)
