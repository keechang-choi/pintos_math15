#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/init.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "lib/string.h"

static void syscall_handler (struct intr_frame *);
struct lock filesys_lock;




void
syscall_init (void) 
{
  
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int args[10];
  
  switch(*(int*)f->esp){
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      get_args(f->esp+4, &args[0], 1);
      exit(args[0]);
      
      break;
    case SYS_EXEC: 
      get_args(f->esp+4, &args[0], 1);
      f->eax = exec((const char*)args[0]);
      break;
    case SYS_WAIT:
      get_args(f->esp+4, &args[0], 1);
      
      f->eax = wait((int)args[0]);
      break;
    case SYS_CREATE:
      get_args(f->esp+4, &args[0], 2);
      f->eax = create((const char*)args[0], (unsigned)args[1]);
      break;
    case SYS_REMOVE:
      get_args(f->esp+4, &args[0], 1);
      f->eax = remove((const char*)args[0]);
      break;
    case SYS_OPEN:
      get_args(f->esp+4, &args[0], 1);
      f->eax = open((const char*)args[0]);
      break;
    case SYS_FILESIZE:
      get_args(f->esp+4, &args[0], 1);
      f->eax = filesize((int)args[0]);
      break;
    case SYS_READ:
      get_args(f->esp+4, &args[0], 3);
      f->eax = read((int)args[0], (void*)args[1],(unsigned)args[2]);
      break;
    case SYS_WRITE:
      get_args(f->esp+4, &args[0], 3);
      f->eax = write((int)args[0],(const void*)args[1], (unsigned int)args[2]);
      break;
    case SYS_SEEK:
      get_args(f->esp+4, &args[0], 2);
      seek((int)args[0], (unsigned)args[1]);
      break;
    case SYS_TELL:
      get_args(f->esp+4, &args[0], 1);
      f->eax = tell((int)args[0]);
      break;
    case SYS_CLOSE:
      get_args(f->esp+4, &args[0], 1);
      close((int)args[0]);
      break;
    default:
      break;              
  }
  
  //printf ("system call! %d\n", *(int*)f->esp);
  //thread_exit ();
}

void halt(){
  shutdown_power_off();
}

void exit(int status){
 
  printf("%s: exit(%d)\n", thread_current()->name,status);
  
   thread_current()->exit_status = status; 
  /*
  struct list_elem* e;
  for(e = list_begin(&thread_current()->files_list); e!=list_end(&thread_current()->files_list); e = list_next(e)){
    struct one_file* temp = list_entry(e, struct one_file, file_elem);
    list_remove(&temp->file_elem);
    free(temp);
  }
   */
  //printf("%s\n",((char *) 0x20101234));
  thread_exit();
}

bool create(const char* file, unsigned initial_size){
  if(file == NULL){
    exit(-1);
  }
  if(!file_available(file))
    exit(-1);
  lock_acquire(&filesys_lock);
  bool file_creation = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  return file_creation;
}

bool remove(const char* file){
  return filesys_remove(file);
}

tid_t exec(const char* cmd_line){
  lock_acquire(&filesys_lock);
  tid_t t = process_execute(cmd_line);
  lock_release(&filesys_lock);
  return t;
}

int wait(tid_t pid){
  return process_wait(pid);
}

int write(int fd, const void* buffer, unsigned size){ 
 if (fd == 1) {
    putbuf(buffer, size);
    return size;
  }
  struct file *file = file_search_by_fd(fd);

  if(file==NULL)
    return -1;
  if(!file_available(buffer))
    exit(-1);

  lock_acquire(&filesys_lock);
  
  off_t written_bytes = file_write(file, buffer, size);
  lock_release(&filesys_lock);
  
  return written_bytes;

}

int open(const char* file){
  if(!file_available(file))
    exit(-1);

  lock_acquire(&filesys_lock);
  struct file* f = filesys_open(file);
  
  if(strcmp(file, thread_current()->name)==0){
    file_deny_write(f);
  }
    
  lock_release(&filesys_lock);
  
  if (f ==NULL)
    return -1; 
  else
  {
    struct one_file* new_file = (struct one_file*)malloc(sizeof(struct one_file));
    new_file->fd = new_fid();
    new_file->file = f;
    list_push_back(&thread_current()->files_list, &new_file->file_elem);
    //file_deny_write(f);
    return new_file->fd;
  } 
}

int read(int fd, void* buffer,  unsigned size){
  if(fd==0){
    return input_getc();
  }

  struct file *file = file_search_by_fd(fd);

  if(file==NULL)
    return -1;
  if(!file_available(buffer))
    exit(-1);

  lock_acquire(&filesys_lock);
  off_t readed_bytes = file_read(file, buffer, size);

  lock_release(&filesys_lock);
  return readed_bytes;
}

int filesize(int fd){
  
  struct file *file = file_search_by_fd(fd);
  if(file==NULL)
    return -1;

  lock_acquire(&filesys_lock);
  off_t file_lengths = file_length(file);  
  lock_release(&filesys_lock);

  return file_lengths;
}

void seek(int fd, unsigned position){
  struct file *file = file_search_by_fd(fd);
  if(file==NULL)
    exit(-1);
  lock_acquire(&filesys_lock);
  file_seek(file, position);
  lock_release(&filesys_lock);
}

unsigned tell(int fd){
  struct file *file = file_search_by_fd(fd);
  if(file==NULL)
    exit(-1);
  lock_acquire(&filesys_lock);
  unsigned position = file_tell(file);
  lock_release(&filesys_lock);
  return position;
}

void close(int fd){
  struct one_file *file = file_search_and_delete_by_fd(fd);
  if(file ==NULL)
    exit(-1);
  lock_acquire(&filesys_lock);

  //file_allow_write(file);
  file_close(file->file);
  
  lock_release(&filesys_lock);
  free(file);
}


void available_addr(void* addr){
  if(!is_user_vaddr(addr)){
    exit(-1);
    return;
  }
}

void get_args(void* esp, int* arg, int count){
  int* temp;
  for(int i = 0; i < count; i++){
    temp = (int*)esp + i;
    available_addr((void*)temp);
    arg[i] = *temp;
  }
}

int file_available(void* addr){
  if (addr >= PHYS_BASE)
    return 0;
  if (addr < 0x08048000)
    return 0;
  if (pagedir_get_page(thread_current()->pagedir, addr) == NULL)
    return 0;
  return 1;
}

int new_fid(void){
  static int fid = 2;
  return fid++;
}

struct file* file_search_by_fd(int fd){
  struct list_elem* e;
  for(e = list_begin(&thread_current()->files_list); e!=list_end(&thread_current()->files_list); e = list_next(e)){
    struct one_file* temp = list_entry(e, struct one_file, file_elem);
    if(temp->fd == fd){
      return temp->file;
    }
  }
  return NULL;
}

struct one_file* file_search_and_delete_by_fd(int fd){
  struct list_elem* e;
  for(e = list_begin(&thread_current()->files_list); e!=list_end(&thread_current()->files_list); e = list_next(e)){
    struct one_file* temp = list_entry(e, struct one_file, file_elem);
    if(temp->fd == fd){
      list_remove(&temp->file_elem);
      
      return temp;
    }
  }
  return NULL;
}