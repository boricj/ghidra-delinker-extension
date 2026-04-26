#include "allocator.h"

#include <stdio.h>
#include <string.h>

/* Heap memory. */
union { void *align_; unsigned char bytes[384]; } s_heap;

/* Chunk structures for the heap. */
struct chunk_32 {
    chunk_header header;
    unsigned char data[32 - sizeof(chunk_header)];
};

struct chunk_64 {
    chunk_header header;
    unsigned char data[64 - sizeof(chunk_header)];
};

struct chunk_96 {
    chunk_header header;
    unsigned char data[96 - sizeof(chunk_header)];
};

struct chunk_192 {
    chunk_header header;
    unsigned char data[192 - sizeof(chunk_header)];
};

struct chunk_384 {
    chunk_header header;
    unsigned char data[384 - sizeof(chunk_header)];
};

/* Heap snapshots structures. */
struct heap_snapshot_1 {
    struct chunk_384 block_1;
};

struct heap_snapshot_2 {
    struct chunk_32 block_1;
    struct chunk_32 block_2;
    struct chunk_32 block_3;
    struct chunk_32 block_4;
    struct chunk_64 block_5;
    struct chunk_64 block_6;
    struct chunk_64 block_7;
    struct chunk_64 block_8;
};

struct heap_snapshot_3 {
    struct chunk_32 block_1;
    struct chunk_32 block_2;
    struct chunk_32 block_3;
    struct chunk_32 block_4;
    struct chunk_64 block_5;
    struct chunk_64 block_6;
    struct chunk_64 block_7;
    struct chunk_64 block_8;
};

struct heap_snapshot_4 {
    struct chunk_32 block_1;
    struct chunk_96 block_2;
    struct chunk_64 block_3;
    struct chunk_192 block_4;
};

struct heap_snapshot_5 {
    struct chunk_384 block_1;
};

/* Heap snapshot values (creates lots of relocations with addends). */
#define FILL_x1(v)  v
#define FILL_x2(v)  FILL_x1(v), FILL_x1(v)
#define FILL_x4(v)  FILL_x2(v), FILL_x2(v)
#define FILL_x8(v)  FILL_x4(v), FILL_x4(v)
#define FILL_x16(v) FILL_x8(v), FILL_x8(v)
#define FILL_x32(v) FILL_x16(v), FILL_x16(v)
#define FILL_x64(v) FILL_x32(v), FILL_x32(v)
#define FILL_x128(v) FILL_x64(v), FILL_x64(v)
#define FILL_x256(v) FILL_x128(v), FILL_x128(v)

#if defined(__LP64__) || defined(_LP64) || defined(_WIN64)
    #define FILL_ADJUST(v)
#else
    #define FILL_ADJUST(v) FILL_x8(v),
#endif

const struct heap_snapshot_1 s_snapshot_1 = {
    {
        { (chunk_header *)0, 384 },
        { FILL_ADJUST(0) FILL_x256(0), FILL_x64(0), FILL_x32(0), FILL_x16(0) }
    }
};

const struct heap_snapshot_2 s_snapshot_2 = {
    { 
        { (chunk_header *)&s_heap.bytes[32], -32 },
        { FILL_ADJUST(1) FILL_x16(1) }
    },
    { 
        { (chunk_header *)&s_heap.bytes[64], -32 },
        { FILL_ADJUST(2) FILL_x16(2) }
    },
    { 
        { (chunk_header *)&s_heap.bytes[96], -32 },
        { FILL_ADJUST(3) FILL_x16(3) }
    },
    { 
        { (chunk_header *)&s_heap.bytes[128], -32 },
        { FILL_ADJUST(4) FILL_x16(4) }
    },
    { 
        { (chunk_header *)&s_heap.bytes[192], -64 },
        { FILL_ADJUST(5) FILL_x32(5), FILL_x16(5) }
    },
    { 
        { (chunk_header *)&s_heap.bytes[256], -64 },
        { FILL_ADJUST(6) FILL_x32(6), FILL_x16(6) }
    },
    { 
        { (chunk_header *)&s_heap.bytes[320], -64 },
        { FILL_ADJUST(7) FILL_x32(7), FILL_x16(7) }
    },
    { 
        { (chunk_header *)0, -64 },
        { FILL_ADJUST(8) FILL_x32(8), FILL_x16(8) }
    }
};

const struct heap_snapshot_3 s_snapshot_3 = {
    { 
        { (chunk_header *)&s_heap.bytes[32], -32 },
        { FILL_ADJUST(1) FILL_x16(1) }
    },
    { 
        { (chunk_header *)&s_heap.bytes[64], 32 },
        { FILL_ADJUST(0) FILL_x16(0) }
    },
    { 
        { (chunk_header *)&s_heap.bytes[96], -32 },
        { FILL_ADJUST(3) FILL_x16(3) }
    },
    { 
        { (chunk_header *)&s_heap.bytes[128], 32 },
        { FILL_ADJUST(0) FILL_x16(0) }
    },
    { 
        { (chunk_header *)&s_heap.bytes[192], -64 },
        { FILL_ADJUST(5) FILL_x32(5), FILL_x16(5) }
    },
    { 
        { (chunk_header *)&s_heap.bytes[256], 64 },
        { FILL_ADJUST(0) FILL_x32(0), FILL_x16(0) }
    },
    { 
        { (chunk_header *)&s_heap.bytes[320], -64 },
        { FILL_ADJUST(7) FILL_x32(7), FILL_x16(7) }
    },
    { 
        { (chunk_header *)0, 64 },
        { FILL_ADJUST(0) FILL_x32(0), FILL_x16(0) }
    }
};

const struct heap_snapshot_4 s_snapshot_4 = {
    { 
        { (chunk_header *)&s_heap.bytes[32], -32 },
        { FILL_ADJUST(1) FILL_x16(1) }
    },
    {
        { (chunk_header *)&s_heap.bytes[128], 96 },
        { FILL_ADJUST(0) FILL_x64(0) }
    },
    { 
        { (chunk_header *)&s_heap.bytes[192], -64 },
        { FILL_ADJUST(5) FILL_x32(5), FILL_x16(5) }
    },
    {
        { (chunk_header *)0, 192 },
        { FILL_ADJUST(0) FILL_x128(0), FILL_x32(0), FILL_x16(0) }
    }
};

const struct heap_snapshot_5 s_snapshot_5 = {
    {
        { (chunk_header *)0, 384 },
        { FILL_ADJUST(0) FILL_x256(0), FILL_x64(0), FILL_x32(0), FILL_x16(0) }
    }
};

/* Heap ranges (creates a one-past-the-end relocation). */
struct heap_range {
    const unsigned char *start;
    const unsigned char *end;
};

const struct heap_range s_heap_ranges[5] = {
    { (const unsigned char *)&s_snapshot_1, (const unsigned char *)&s_snapshot_1 + sizeof(s_snapshot_1) },
    { (const unsigned char *)&s_snapshot_2, (const unsigned char *)&s_snapshot_2 + sizeof(s_snapshot_2) },
    { (const unsigned char *)&s_snapshot_3, (const unsigned char *)&s_snapshot_3 + sizeof(s_snapshot_3) },
    { (const unsigned char *)&s_snapshot_4, (const unsigned char *)&s_snapshot_4 + sizeof(s_snapshot_4) },
    { (const unsigned char *)&s_snapshot_5, (const unsigned char *)&s_snapshot_5 + sizeof(s_snapshot_5) }
};

static void* allocate_and_fill(void *heap, size_t size, unsigned char pattern) {
    void *ptr = freelist_alloc(heap, size - sizeof(chunk_header));

    if (ptr == NULL) {
        return NULL;
    }

    memset(ptr, pattern, size - sizeof(chunk_header));
    return ptr;
}

int main(void) {
    void *heap = (void *) s_heap.bytes;
    void *allocations[8];
    size_t i;
    int ret;

    /* Check initial heap state. */
    freelist_init(heap, 384);

    ret = memcmp(heap, s_heap_ranges[0].start, s_heap_ranges[0].end - s_heap_ranges[0].start);
    if (ret != 0) {
        return ret;
    }

    /* Check full heap state. */
    for (i = 0; i < 8; i++) {
        allocations[i] = allocate_and_fill(heap, i < 4 ? 32 : 64, i + 1);
    }

    ret = memcmp(heap, s_heap_ranges[1].start, s_heap_ranges[1].end - s_heap_ranges[1].start);
    if (ret != 0) {
        return ret;
    }

    /* Check heap with free chunks. */
    for (i = 1; i < 8; i += 2) {
        freelist_free(heap, allocations[i]);
    }

    ret = memcmp(heap, s_heap_ranges[2].start, s_heap_ranges[2].end - s_heap_ranges[2].start);
    if (ret != 0) {
        return ret;
    }

    /* Check free chunk coalescing. */
    for (i = 2; i < 8; i += 4) {
        freelist_free(heap, allocations[i]);
    }

    ret = memcmp(heap, s_heap_ranges[3].start, s_heap_ranges[3].end - s_heap_ranges[3].start);
    if (ret != 0) {
        return ret;
    }

    /* Check final empty heap state. */
    for (i = 0; i < 8; i += 4) {
        freelist_free(heap, allocations[i]);
    }
    
    ret = memcmp(heap, s_heap_ranges[4].start, s_heap_ranges[4].end - s_heap_ranges[4].start);
    if (ret == 0) {
        puts("All tests passed.");
    }

    return ret;
}
