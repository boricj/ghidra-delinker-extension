#ifndef FREELIST_ALLOCATOR_ALLOCATOR_H
#define FREELIST_ALLOCATOR_ALLOCATOR_H

#include <stddef.h>

#define ALIGNMENT (sizeof(void *))
#define MIN_CHUNK_SIZE (2 * sizeof(chunk_header))

typedef struct chunk_header chunk_header;

struct chunk_header {
    chunk_header *next;
    ptrdiff_t length;
};

void freelist_init(void *heap, size_t heap_size);
void *freelist_alloc(void *heap, size_t size);
void freelist_free(void *heap, void *ptr);

#endif
