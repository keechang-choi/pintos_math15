#ifndef VM_FRAME_H
#define VM_FRAME_H
#include <hash.h>
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/synch.h" 

struct frame_entry{
    void* uaddr;
    void* kaddr;
    struct thread* thread;
    struct hash_elem frame_elem;
};





struct hash frame_table;
struct hash_iterator* frame_table_clock;
struct lock frame_lock;
int clock_index;

void frame_init(void);
int frame_val(struct hash_elem* , void* );
bool frame_less(struct hash_elem* , struct hash_elem*, void* );
bool frame_insert(void* , void* );
void* frame_get_page(enum palloc_flags , void* );
void frame_free_page(void* );
void frame_delete_by_thread_exit(struct thread*);
/* sibal */


#endif