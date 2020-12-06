#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "vm/suppage.h"


tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

bool handle_page_faultt(struct sup_table_entry* sup_entry);
bool stack_growth(void **esp, void *fault_addr);
#endif /* userprog/process.h */
