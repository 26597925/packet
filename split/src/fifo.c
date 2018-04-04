#include "fifo.h"

queue_t *fifo_init(int max_size)
{
	queue_t * new_queue = (queue_t*)malloc(sizeof(queue_t));
	if(new_queue == NULL) 
	{
	   return NULL;
	}
	new_queue->max_size = max_size;
	new_queue->first = NULL;
	new_queue->last = NULL;

	new_queue->current_size = 0;
	
	pthread_mutex_init(&new_queue->mutex,NULL);;

   return new_queue;
}

void fifo_free(queue_t * queue)
{
    if(queue == NULL) 
	{
        return;
    }

    pthread_mutex_lock(&queue->mutex);
    if(queue->first == NULL) 
	{
        free(queue);
        pthread_mutex_unlock(&queue->mutex);
        return;
    }

    node_t * _node = queue->first;

    while(_node != NULL) 
	{
        free(_node->data);
        node_t *tmp = _node->next;
        free(_node);
        _node = tmp;
    }

    free(queue);

    pthread_mutex_unlock(&queue->mutex);
}

int fifo_push(queue_t * queue, void * data, int size)
{
	node_t * new_node = (node_t*)malloc(sizeof(node_t));
	if(new_node == NULL) 
	{
		return -1;
	}
	new_node->data = data;
	new_node->size = size;
	new_node->next = NULL;
	pthread_mutex_lock(&queue->mutex);

	if (queue->first == NULL) 
	{
		queue->first = new_node;
		queue->last = new_node;
	} else 
	{
		queue->last->next = new_node;
		queue->last = new_node;
	}
	queue->current_size ++;
	pthread_mutex_unlock(&queue->mutex);
	return 0;
}

void * fifo_pop(queue_t * queue, int *dataLen)
{
	if (queue == NULL) 
	{
		return NULL;
	}

	pthread_mutex_lock(&queue->mutex);
	if (queue->first == NULL) 
	{
		pthread_mutex_unlock(&queue->mutex);
		return NULL;
	}

	void * data;
	node_t * _node = queue->first;
	if (queue->first == queue->last) 
	{
		queue->first = NULL;
		queue->last = NULL;
	} else 
	{
		queue->first = _node->next;
	}
	data = _node->data;
	*dataLen = _node->size;

	free(_node);
	queue->current_size--;
	pthread_mutex_unlock(&queue->mutex);
	return data;
}

int fifo_count(queue_t * queue)
{
	if(queue == NULL) return 0;

	int count=0;
	pthread_mutex_lock(&queue->mutex);
    node_t * _node = queue->first;
    while(_node != NULL) {
    	_node = _node->next;
    	count++;
    }
    pthread_mutex_unlock(&queue->mutex);
    return count;
}

int fifo_full(queue_t * queue)
{
	return (queue->max_size <= queue->current_size) ;
}
