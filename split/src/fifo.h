#ifndef FIFO_H
#define FIFO_H

#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

typedef struct node {
	int size;
	void *data;
	struct node_t *next;
} node_t;

typedef struct queue {
	int max_size;
	int current_size;
	node_t *first;
	node_t *last;
	pthread_mutex_t mutex;
} queue_t;

queue_t *fifo_init(int max_size);

void fifo_free(queue_t *queue);

int fifo_push(queue_t *queue, void *data, int size);

void *fifo_pop(queue_t *queue, int *dataLen);

int fifo_count(queue_t *queue);

int fifo_full(queue_t *queue);

#endif
