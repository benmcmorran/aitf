all: server client
	g++ -o "DISRD" "network_daemon2.cpp" -pthread
server: web_server.o
	gcc web_server.o -o server -lpthread
web_server.o: web_server.c web_server.h
	gcc -c web_server.c -lpthread
client: flow.o
	gcc flow.o -o flow
flow.o: flow.c
	gcc -c flow.c
clean:
	rm -rf web_server.o server
	rm -rf flow.o client

