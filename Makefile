all:
	gcc -lnetfilter_queue -trigraphs RR_subterfuge.c -o RR_sub 