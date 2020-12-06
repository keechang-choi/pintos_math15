#include "vm/frame.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/swap.h"
#include "vm/suppage.h"
#include <stdlib.h>

void frame_init(void){
    lock_init(&frame_lock);
    hash_init(&frame_table, frame_val, frame_less, NULL);
    clock_index = 0;
    frame_table_clock = malloc(sizeof(struct hash_iterator));
}

int frame_val(struct hash_elem* hash, void* aux){
    struct frame_entry* frame = hash_entry(hash, struct frame_entry, frame_elem);
    return hash_int(frame->kaddr);
}
bool frame_less(struct hash_elem* a, struct hash_elem* b, void* aux){
    struct frame_entry* frame_a = hash_entry(a, struct frame_entry, frame_elem);
    struct frame_entry* frame_b = hash_entry(b, struct frame_entry, frame_elem);
    return frame_a->kaddr < frame_b->kaddr;
}
bool frame_insert(void* uaddr, void* kaddr){
    struct frame_entry* frame = malloc(sizeof(struct frame_entry));
    frame->kaddr = kaddr;
    frame->uaddr = uaddr;
    frame->thread = thread_current();
    if(hash_insert(&frame_table, &frame->frame_elem) == NULL){
        return true;
    }
    else
    {
        return false;
    }
}

void* frame_get_page(enum palloc_flags flags, void* uaddr){
    if(!(flags & PAL_USER))
        return NULL;
    //lock_acquire(&frame_lock);
    uint8_t* frame = palloc_get_page(flags);

    /* free-page left*/
    if(frame!= NULL){
        frame_insert(uaddr, frame);
        //return frame;
    }
    else{
	//return NULL;
        //printf("evict at %x\n", uaddr);
       
        hash_first(frame_table_clock, &frame_table);

        int frame_table_size = hash_size(&frame_table);
	//to last clock position
        int i = 0;
        while(i < clock_index){
            hash_next(frame_table_clock);
            i += 1;
        }

	while(1){
	    //if clock ended at last
            if(!hash_next(frame_table_clock)){
                hash_first(frame_table_clock, &frame_table);
                hash_next(frame_table_clock);
                clock_index = 0;
            }
            clock_index ++;
            struct frame_entry* frame_entry = hash_entry(hash_cur(frame_table_clock), struct frame_entry, frame_elem);
            if(frame_entry == NULL)
		PANIC ("EVICT ERR");
            //printf("%x %x %d\n", frame_entry->kaddr, frame_entry->uaddr, frame_entry->thread->tid);
            if(!pagedir_is_accessed(thread_current()->pagedir, frame_entry->uaddr) ){
                /* swap! */
                void* kaddr = frame_entry->kaddr;
                
                /* reflect changes... */
                struct thread* target_thread = frame_entry->thread;
                void* target_uaddr = frame_entry->uaddr;
                
                struct sup_table_entry* sup_entry = sup_find_entry(&target_thread->sup_table, target_uaddr);
                
                int free_flag = 0;
                switch(sup_entry->type){
                    case NORMAL:
                        //printf("%x go to swap_table\n", sup_entry->uaddr);
                        if(pagedir_is_dirty(target_thread->pagedir, pg_round_down(target_uaddr))){
                            //printf("now..%x %x\n", frame_entry->kaddr, frame_entry->uaddr);
                            sup_entry->swap_index = swap_out(frame_entry->kaddr);
                            sup_entry->type = SWAP;
                        }
                       
                                   
                        break;
                    case MMAP_FILE:
                        if(pagedir_is_dirty(target_thread->pagedir, pg_round_down(target_uaddr)))
                            file_write_at(sup_entry->file, sup_entry->uaddr, sup_entry->read_bytes, sup_entry->offset); 
                       
                        break;
                    case SWAP:             
                        //printf("swap + %x\n", frame_entry->uaddr);
                        sup_entry->swap_index = swap_out(frame_entry->kaddr);
                        break;
                    default:
                        break;
                }
                /*
                if(target_uaddr>=0xbfff0000)
                    printf("%x go to swap\n", target_uaddr);
                */

                frame_free_page_2(frame_entry);
                //printf("@@@evicted\n"); 
               
                kaddr = palloc_get_page(flags);

                if(kaddr == NULL)
                    PANIC ("why not removed?\n");
                
                frame_insert(uaddr, kaddr);
                //lock_release(&frame_lock);
                frame = kaddr;
               
                break;
            }
            else{
                pagedir_set_accessed(thread_current()->pagedir, frame_entry->uaddr,false);
            }    
            if (clock_index >= frame_table_size){
                hash_first(frame_table_clock, &frame_table);    
                clock_index = 0;
            }
        } 
    }
    return frame;
}



void frame_free_page(void* frame){
  //  lock_acquire(&frame_lock);
    struct frame_entry* real_frame;
    real_frame->kaddr = frame;

    struct hash_elem* e = hash_delete(&frame_table, &real_frame->frame_elem);

    palloc_free_page(frame);

    if(e!= NULL)
        free(hash_entry(e, struct frame_entry, frame_elem));
   // palloc_free_page(real_frame->kaddr);
    else
        PANIC("why..?\n");
  //  lock_release(&frame_lock);
}

void frame_free_page_2(struct frame_entry* frame_entry){


    //lock_acquire(&frame_lock);

    struct hash_elem* e = hash_delete(&frame_table, &frame_entry->frame_elem);
    //lock_release(&frame_lock);
    pagedir_clear_page(frame_entry->thread->pagedir, frame_entry->uaddr);
    palloc_free_page(frame_entry->kaddr);

    if(e!= NULL)
        free(frame_entry);
    else
        PANIC("why..?\n");

}
void frame_delete_by_thread_exit(struct thread* cur){
    struct hash_iterator i;

    hash_first (&i, &frame_table);
    while (hash_next (&i))
    {
        struct frame_entry *f = hash_entry (hash_cur (&i), struct frame_entry, frame_elem);
        if (f->thread == cur){
            frame_free_page(f);
        }
    }
}
