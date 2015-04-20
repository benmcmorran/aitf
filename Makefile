all:
	g++ -g -o rr main.c RR.cpp RREntry.cpp Utils.cpp -ltins -lnetfilter_queue