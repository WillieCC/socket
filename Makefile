SERVER_OBJS = test_server.o
 
CLIENT_OBJS = test_client.o

CFLAGS = -Wall -Wextra -O3
 
default:all
all: server client
 
server: $(SERVER_OBJS)
	$(CC) -o $@ $^
 
client: $(CLIENT_OBJS)
	$(CC) -o $@ $^
 
clean:
	rm -vrf *.o server client
