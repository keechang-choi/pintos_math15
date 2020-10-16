#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
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
#endif /* userprog/syscall.h */
