#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "threads/thread.h"
typedef int tid_t;


void syscall_init (void);




void available_addr(void*);
void get_args(void*, int*, int);
void halt();
void exit(int);
bool create(const char*, unsigned);
bool remove(const char*);
int write(int, const void*, unsigned);
tid_t exec(const char*);
int wait(tid_t);

int open(const char*);
int filesize(int);
int read(int, void*,  unsigned);
void seek(int, unsigned);
unsigned tell(int);
void close(int);

int mmap(int, void*);
void munmap(int mapid);
bool valid_addr(void* addr);

struct file* file_search_by_fd(int);
struct file* file_search_and_delete_by_fd(int);


#endif /* userprog/syscall.h */
