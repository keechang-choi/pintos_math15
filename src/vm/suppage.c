#include "vm/suppage.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

void sup_table_init(struct hash* sup_table){
    hash_init(sup_table, sup_val, sup_less, NULL);
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
    if (sup_elem == NULL)
        return NULL;
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
    palloc_free_page(pagedir_get_page(cur_thread->pagedir, sup_entry->uaddr));

    free(sup_entry);
}

void sup_table_destroy(struct hash* sup_table){
    hash_destroy(sup_table, sup_destroy_func);
}


bool sup_load_file(void* kaddr, struct sup_table_entry* sup_entry){
    if(sup_entry->file){
       
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
    
    return false;
}

