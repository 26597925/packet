#include "queue.h"

queue_t *init_queue(int size)
{
	queue_t * new_queue = (queue_t*)malloc(sizeof(queue_t));
	if(new_queue == NULL) 
	{
	   return NULL;
	}
	
	new_queue->buf = (uint8_t*)av_mallocz(sizeof(uint8_t)*size);
	new_queue->read_ptr = new_queue->write_ptr = 0;
	new_queue->bufsize = size;
	
	pthread_mutex_init(&new_queue->locker, NULL);
	pthread_cond_init(&new_queue->cond, NULL);
	
	return new_queue;
}

void put_queue(queue_t *que, uint8_t* buf, int size)
{
	uint8_t* dst = que->buf + que->write_ptr;

	pthread_mutex_lock(&que->locker);

	if ((que->write_ptr + size) > que->bufsize) {
		memcpy(dst, buf, (que->bufsize - que->write_ptr));
		memcpy(que->buf, buf+(que->bufsize - que->write_ptr), size-(que->bufsize - que->write_ptr));
	} else {
		memcpy(dst, buf, size*sizeof(uint8_t));
	}
	que->write_ptr = (que->write_ptr + size) % que->bufsize;

	pthread_cond_signal(&que->cond);
	pthread_mutex_unlock(&que->locker);
}

int get_queue(queue_t *que, uint8_t* buf, int size)
{
	uint8_t* src = que->buf + que->read_ptr;
	int wrap = 0;

	pthread_mutex_lock(&que->locker);

	int pos = que->write_ptr;

	if (pos < que->read_ptr) {
		pos += que->bufsize;
		wrap = 1;
	}

	if ( (que->read_ptr + size) > pos) {
		pthread_mutex_unlock(&que->locker);
		return 1;
	}

	if (wrap) {
		fprintf(stdout, "wrap...\n");
		memcpy(buf, src, (que->bufsize - que->read_ptr));
		memcpy(buf+(que->bufsize - que->read_ptr), src+(que->bufsize - que->read_ptr), size-(que->bufsize - que->read_ptr));
	} else {
		memcpy(buf, src, sizeof(uint8_t)*size);
	}
	que->read_ptr = (que->read_ptr + size) % que->bufsize;
	pthread_mutex_unlock(&que->locker);
}

void free_queue(queue_t *que)
{
	pthread_mutex_destroy(&que->locker);
	pthread_cond_destroy(&que->cond);
	av_free(que->buf);
}