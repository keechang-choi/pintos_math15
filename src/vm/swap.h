#ifndef VM_SWAP
#define VM_SWAP

#include "lib/kernel/bitmap.h"
#include "devices/block.h"
#include "threads/synch.h"

struct block* swap_table;
struct lock swap_lock;
struct bitmap* swap_bitmap;

void swap_init(void);
void swap_in(size_t, void*);
size_t swap_out(void*);

#endif