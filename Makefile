all:
	g++ -g -o rr main.c RR.cpp RREntry.cpp HostMapping.cpp HostMappingReader.cpp Utils.cpp -ltins -lnetfilter_queue