all:
	g++ -g -o rr main.c RR.cpp RREntry.cpp HostMapping.cpp HostMappingReader.cpp Utils.cpp AITF_daemon.cpp AITF_connect_state.cpp RRFilter.cpp AITF_packet.cpp AITF_identity.cpp AITF_filter.cpp -ltins -lnetfilter_queue -pthread

