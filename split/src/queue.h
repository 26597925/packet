#ifndef __QUEUE_H__
#define __QUEUE_H__

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pthread.h>

typedef struct queue {
	pthread_mutex_t locker;
	pthread_cond_t cond;
	uint8_t* buf;
	int buf_size;
	int write_ptr;
	int read_ptr;
} queue_t;

queue_t *init_queue(int size);

void free_queue(queue_t *que);

void put_queue(queue_t *que, uint8_t* buf, int size);

int get_queue(queue_t *que, uint8_t* buf, int size);

#endif