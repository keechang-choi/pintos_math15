#include "vm/suppage.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "vm/frame.h"
#include "devices/timer.h"
#include <stdlib.h>

void sup_table_init(struct hash* sup_table){
    hash_init(sup_table, sup_val, sup_less, NULL);
    lock_init(&sup_lock);
}

int sup_val(struct hash_elem* hash, void* aux){
    struct sup_table_entry* sup_entry = hash_entry(hash, struct sup_table_entry, sup_elem);
    return hash_int(sup_entry->uaddr);
}

bool sup_less(struct hash_elem* a, struct hash_elem* b, void* aux){
    struct sup_table_entry* sup_a = hash_entry(a, struct sup_table_entry, sup_elem);
    struct sup_table_entry* sup_b = hash_entry(b, struct sup_table_entry, sup_elem);
    return sup_a->uaddr < sup_b->uaddr;
}

bool sup_insert(struct hash* sup_table, struct sup_table_entry* sup_entry){
    return (hash_insert(sup_table, &sup_entry->sup_elem) == NULL);
}

bool sup_delete(struct hash* sup_table, struct sup_table_entry* sup_entry){
    return (hash_delete(sup_table, &sup_entry->sup_elem));
}

struct sup_table_entry* sup_find_entry(struct hash* sup_table, void* uaddr){
    void* real_uaddr = pg_round_down(uaddr);
    struct sup_table_entry temp_s;
    temp_s.uaddr = real_uaddr;
    struct hash_elem* sup_elem = hash_find(sup_table, &temp_s.sup_elem);
    if (sup_elem == NULL){
        return NULL;
    }       
    else
    {
        return hash_entry(sup_elem, struct sup_table_entry, sup_elem);
    }    
}

void sup_destroy_func(struct hash_elem* h, void* aux){
    struct thread* cur_thread = thread_current();
    struct sup_table_entry* sup_entry = hash_entry(h, struct sup_table_entry, sup_elem);
    if(sup_entry == NULL)
        return;
        pagedir_clear_page(cur_thread->pagedir, sup_entry->uaddr);
    /*void* kaddr = pagedir_get_page(cur_thread->pagedir, sup_entry->uaddr);
    if(!kaddr){
	frame_free_page(kaddr);
        free(sup_entry);
        return;
    }
    return;
*/
    void* kaddr;
    switch(sup_entry->type){
    case NORMAL:
        kaddr = pagedir_get_page(cur_thread->pagedir, sup_entry->uaddr);
	pagedir_clear_page(cur_thread->pagedir, sup_entry->uaddr);
	if(kaddr == NULL){
	;  
	//PANIC ("@@@@@no page for uaddr\n");
	}else{
	  
	  frame_free_page(kaddr);
	}

	break;
    case MMAP_FILE:
	if(pagedir_is_dirty(cur_thread->pagedir, pg_round_down(sup_entry->uaddr)))
	    file_write_at(sup_entry->file, sup_entry->uaddr, sup_entry->read_bytes, sup_entry->offset); 
       
	break;
	
    case SWAP:             
	//printf("@@@@@supswap\n");
	if (sup_entry->swap_index == -1){
          kaddr = pagedir_get_page(cur_thread->pagedir, sup_entry->uaddr);
          pagedir_clear_page(cur_thread->pagedir, sup_entry->uaddr);
          if(kaddr == NULL){
            //PANIC("HELP_ME_SWAP\n");
	  }else{
            frame_free_page(kaddr);
	  }
        }
        else
	  swap_bit(sup_entry->swap_index);
	break;
	
    default:
	break;
    }
    

    free(sup_entry);
    
}

void sup_table_destroy(struct hash* sup_table){
   // lock_acquire(&frame_lock);
    hash_destroy(sup_table, sup_destroy_func);
   // lock_release(&frame_lock);
}


bool sup_load_file(void* kaddr, struct sup_table_entry* sup_entry){
    if(sup_entry->file){
        if(sup_entry->read_bytes >0){
    
            size_t actual_read_bytes = file_read_at(sup_entry->file, kaddr, sup_entry->read_bytes,  sup_entry->offset);
        
            if(actual_read_bytes != sup_entry->read_bytes){
                pagedir_clear_page(thread_current()->pagedir, sup_entry->uaddr);
  
                return false;
            }    
            else
            {
                memset(kaddr + actual_read_bytes, 0, sup_entry->zero_bytes);
            }
            return true; 
        }
        /* all_zero page */
        else{
            
            ASSERT(sup_entry->zero_bytes == PGSIZE);
            memset(kaddr, 0, sup_entry->zero_bytes);
            return true;
        }
    }

    return false;
}


bool mmap_create_sup_entries(struct mmap_entry* mmap_entry, void* addr){
    struct file* file = mmap_entry->file;
    int read_bytes = file_length(file);
    int zero_bytes = 0;
    int ofs = 0;
    bool success = true;
    addr = pg_round_down(addr);

    struct sup_table_entry check_entry;
    file_seek (file, ofs);
    while(read_bytes > 0){
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* handle mmap overlap */
        if (sup_find_entry(&thread_current()->sup_table, addr) != NULL){
            success = false;
            break;
        }

        struct sup_table_entry* sup_entry = malloc(sizeof(struct sup_table_entry));
        sup_entry->type = MMAP_FILE;
        sup_entry->uaddr = pg_round_down(addr);
        sup_entry->writable = true;
        sup_entry->is_loaded = false;
        sup_entry->file = file;
        sup_entry->offset = ofs;
        sup_entry->read_bytes = page_read_bytes;
        sup_entry->zero_bytes = page_zero_bytes;
        sup_insert(&thread_current()->sup_table, sup_entry);
        list_push_back(&mmap_entry->sup_entry_list, &sup_entry->m_sup_elem);
        //printf("%d %d %d %x %d\n", read_bytes, zero_bytes, ofs, sup_entry->uaddr, sup_entry->offset);
        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        ofs += page_read_bytes;
        addr += PGSIZE;
    }

    return success;
}

void mmap_delete_sup_list(struct mmap_entry* mmap_entry, struct hash* sup_table){
    while (!list_empty (&mmap_entry->sup_entry_list))
     {
       struct list_elem *e = list_pop_front (&mmap_entry->sup_entry_list);
       struct sup_table_entry* sup_entry = list_entry(e, struct sup_table_entry, m_sup_elem);

        /* appling changes in file through munmap */
       if(pagedir_is_dirty(thread_current()->pagedir, sup_entry->uaddr)){
           file_write_at(sup_entry->file, sup_entry->uaddr, sup_entry->read_bytes, sup_entry->offset);
       }
       sup_delete(sup_table, sup_entry);
       pagedir_clear_page(thread_current()->pagedir, sup_entry->uaddr);
       palloc_free_page(pagedir_get_page(thread_current()->pagedir, sup_entry->uaddr));
       free(sup_entry);
     }
    return;
} 
