all: server client
server: server.o
	gcc server.o -o server
server.o: server.c
	gcc -c server.c
client: flow.o
	gcc flow.o -o flow
flow.o: flow.c
	gcc -c flow.c
clean:
	rm -rf server.o server
	rm -rf flow.o client
