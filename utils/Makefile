all: server client
server: server.o
	gcc server.o -o server -lpthread
server.o: server.c
	gcc -c server.c -lpthread
client: flow.o
	gcc flow.o -o flow
flow.o: flow.c
	gcc -c flow.c
clean:
	rm -rf server.o server
	rm -rf flow.o client
