CC = i686-w64-mingw32-gcc
CFLAGS = -g -lws2_32
#CC = gcc


all: server client

server: server.c
	$(CC) -o server server.c $(CFLAGS)

client: client.c
	$(CC) -o client client.c $(CFLAGS)

clean:
	rm -f server client
