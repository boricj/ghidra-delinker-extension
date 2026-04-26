#include "allocator.h"

#include <string.h>

static size_t align_up(size_t value) {
    size_t m = ALIGNMENT - 1u;
    return (value + m) & ~m;
}

static size_t chunk_length(const chunk_header *chunk) {
    return (size_t) (chunk->length > 0 ? chunk->length : -chunk->length);
}

static int chunk_is_used(const chunk_header *chunk) {
    return chunk->length < 0;
}

static void chunk_set_used(chunk_header *chunk, int used) {
    if (chunk_is_used(chunk) == used) {
        return;
    }

    chunk->length = -chunk->length;
}

static void chunk_write(chunk_header *chunk, chunk_header *next, size_t length, int used) {
    chunk->next = next;
    chunk->length = used ? -((ptrdiff_t) length) : (ptrdiff_t) length;
}

static unsigned char *chunk_to_data(chunk_header *chunk) {
    return ((unsigned char *) chunk) + sizeof(chunk_header);
}

static chunk_header *chunk_from_data(void *ptr) {
    return (chunk_header *) (((unsigned char *) ptr) - sizeof(chunk_header));
}

static void chunk_split(chunk_header *chunk, size_t requested) {
    chunk_header *new_chunk = (chunk_header *) (((unsigned char *) chunk) + requested);
	size_t new_len = chunk_length(chunk) - requested;

    /* Next chunk can't be smaller than the minimum chunk size. */
	if (new_len < MIN_CHUNK_SIZE) {
		return;
	}

    chunk_write(new_chunk, chunk->next, new_len, 0);
    chunk_write(chunk, new_chunk, requested, chunk_is_used(chunk));
}

void freelist_init(void *heap, size_t heap_size) {
    chunk_write((chunk_header *) heap, NULL, heap_size, 0);
}

void *freelist_alloc(void *heap, size_t size) {
    size_t requested = sizeof(chunk_header) + align_up(size);
    chunk_header *cur;

    if (size == 0u) {
        return NULL;
    }

    /* Allocated chunk can't be smaller than the minimum chunk size. */
	if (requested < MIN_CHUNK_SIZE) {
		requested = MIN_CHUNK_SIZE;
	}

    /* First-fit search for a free chunk of sufficient size. */
    for (cur = (chunk_header *) heap; cur != NULL; cur = cur->next) {
        if (!chunk_is_used(cur) && chunk_length(cur) >= requested) {
            chunk_split(cur, requested);
            chunk_set_used(cur, 1);

            return chunk_to_data(cur);
        }
    }

    return NULL;
}

void freelist_free(void *heap, void *ptr) {
    chunk_header *chunk;

    if (ptr == NULL) {
        return;
    }

    /* Mark chunk as free. */
    chunk = chunk_from_data(ptr);
    chunk_set_used(chunk, 0);
    memset(ptr, 0, chunk_length(chunk) - sizeof(chunk_header));

    /* Coalesce adjacent free chunks. */
    chunk = (chunk_header *) heap;
    while (chunk != NULL && chunk->next != NULL) {
        if (!chunk_is_used(chunk) && !chunk_is_used(chunk->next)) {
            void* old_next = chunk->next;

            chunk_write(chunk, chunk->next->next, chunk_length(chunk) + chunk_length(chunk->next), 0);
            memset(old_next, 0, sizeof(chunk_header));
        } else {
            chunk = chunk->next;
        }
    }
}
