#include "vm/swap.h"
#include "devices/block.h"
#include "lib/kernel/bitmap.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include <stdio.h>

static size_t sectors_in_page = PGSIZE / BLOCK_SECTOR_SIZE;

void swap_init(){
   
    swap_table = block_get_role(BLOCK_SWAP);
    if(swap_table == NULL)
        PANIC("no answer.. cannot create swap table");

    swap_bitmap = bitmap_create(block_size(swap_table) / sectors_in_page);
    bitmap_set_all(swap_bitmap, true);
    lock_init(&swap_lock);
    return;
}

void swap_in(size_t used_index, void* kaddr){
    //printf("used_index is %d\n", used_index);
   // bitmap_dump(swap_bitmap);
    ASSERT(!bitmap_test(swap_bitmap, used_index));
    lock_acquire(&swap_lock);
    int sector = 0;
    while(sector < sectors_in_page){
        block_read(swap_table, used_index* sectors_in_page + sector, kaddr + (sector * BLOCK_SECTOR_SIZE));
        sector+=1;
    }

    bitmap_flip(swap_bitmap, used_index);
    lock_release(&swap_lock);
    return;
}

size_t swap_out(void* kaddr){
    lock_acquire(&swap_lock);
    size_t index = bitmap_scan_and_flip(swap_bitmap, 0, 1, true);
    
    if(index == BITMAP_ERROR){
        return -1;
    }
    
    int sector = 0;
    while(sector < sectors_in_page){
        block_write(swap_table, index * sectors_in_page + sector, kaddr + (sector * BLOCK_SECTOR_SIZE));

        sector += 1;
    }

    lock_release(&swap_lock);

    return index;
}

