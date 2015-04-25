all: server client policy
server: server.o
	gcc server.o -o server
server.o: server.c
	gcc -c server.c
client: flow.o
	gcc flow.o -o flow
flow.o: flow.c
	gcc -c flow.c
policy: policy.c
	g++ -o policy policy.c ../AITF_packet.cpp ../AITF_identity.cpp ../RRFilter.cpp ../RREntry.cpp ../Utils.cpp -ltins -lpthread
clean:
	rm -rf server.o server
	rm -rf flow.o client
