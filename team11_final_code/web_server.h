/*
John Breen
Andrew Botelho
Iveri Prangishvili
*/

#ifndef SERVER_H
#define SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/resource.h>
#include <asm/errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <malloc.h>
#include <string.h>

int             WorkThread( void * );            
unsigned int    CreateAThread( void *, int *);   

#endif
