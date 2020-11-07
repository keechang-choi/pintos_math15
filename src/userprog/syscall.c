#include "userprog/syscall.h"
#include <stdio.h>
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

int open_count = 0;
int close_count = 0;


void
syscall_init (void) 
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int args[5];
  //printf("system call start!\n");
  //printf ("system call %d!\n", *(int*)f->esp);
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
      open_count++;
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
      exit(-1);
      break;              
  }
	
//  printf ("system call %d!\n", *(int*)f->esp);

//  thread_exit ();
}



void halt(){
  shutdown_power_off();
}

void exit(int status){
 
  printf("%s: exit(%d)\n", thread_current()->name,status);

  //sema_down(&thread_current()->exits_sema);
   thread_current()->exit_status = status; 
   thread_current()->exit_flag = true;
   

  //lock_acquire(&filesys_lock); 
  int index = thread_current()->file_number;
  if(index>0){
    for(int i=0; i<index; i++){
      file_close(thread_current()->files_list[i].file);
      close_count++;
    }
  }
  //lock_release(&filesys_lock);


  if(thread_current()->executable != NULL){
  	file_close(thread_current()->executable);
  }
  
  thread_current()->file_number = 0;

  struct list_elem* e;
  struct thread* t, *next;
  for (e = list_begin(&thread_current()->child_list); e != list_end(&thread_current()->child_list); e = next) {
    t = list_entry(e, struct thread, child_elem);
    process_wait(t->tid);
    next = list_next(e);  
  }

  //sema_up(&thread_current()->exits_sema);
  
  sema_up(&thread_current()->waiting_sema);
  sema_down(&thread_current()->exit_sema);

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
  //printf("exec syscal : %s\n", cmd_line);
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
  //printf("@@open : %s\n", file);
  if(!file_available(file))
    exit(-1);

  if(file == NULL)
	  return -1;
  lock_acquire(&filesys_lock);
  struct file* f = filesys_open(file);
  //printf("file f : %p\n", f); 
  //if(thread_current()->tid==5)
  //  printf("file open.. %x\n",(unsigned)f);
  /*if(strcmp(file, thread_current()->name)==0){
 
  //  file_deny_write(f);
  }*/
    
  lock_release(&filesys_lock);
  if (f ==NULL)
    return -1; 
  else
  {
    int index = thread_current()->file_number;
    thread_current()->files_list[index].fd = thread_current()->fd;
    thread_current()->files_list[index].file = f;
    thread_current()->file_number +=1;
    thread_current()->fd += 1;
   
    return thread_current()->files_list[index].fd;
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

  if(!is_user_vaddr(buffer))
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
  struct file *file = file_search_and_delete_by_fd(fd);
  if(file ==NULL)
    exit(-1);
  lock_acquire(&filesys_lock);

  //file_allow_write(file);
  file_close(file);
  
  lock_release(&filesys_lock);
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
  return 1;
  if (addr >= PHYS_BASE)
    return 0;
  if (addr < 0x08048000)
    return 0;
  if (pagedir_get_page(thread_current()->pagedir, addr) == NULL)
    return 0;
  return 1;
}


struct file* file_search_by_fd(int fd){
 /*
  struct list_elem* e;
  for(e = list_begin(&thread_current()->files_list); e!=list_end(&thread_current()->files_list); e = list_next(e)){
    struct one_file* temp = list_entry(e, struct one_file, file_elem);
    if(temp->fd == fd){
      return temp->file;
    }
  }
  return NULL;
  */
 for (int i=0; i<thread_current()->file_number; i++){
   if (thread_current()->files_list[i].fd == fd)
    return thread_current()->files_list[i].file;
 }
 return NULL;

}

struct file* file_search_and_delete_by_fd(int fd){
  /*
  struct list_elem* e;
  for(e = list_begin(&thread_current()->files_list); e!=list_end(&thread_current()->files_list); e = list_next(e)){
    struct one_file* temp = list_entry(e, struct one_file, file_elem);
    if(temp->fd == fd){
      list_remove(&temp->file_elem);
      
      return temp;
    }
  }
  return NULL;
  */
  for (int i=0; i<thread_current()->file_number; i++){
   if (thread_current()->files_list[i].fd == fd){
     struct file* file = thread_current()->files_list[i].file;
     int end = thread_current()->file_number -1;
     thread_current()->files_list[i].file = thread_current()->files_list[end].file;
     thread_current()->files_list[i].fd = thread_current()->files_list[end].fd;
     thread_current()->file_number -=1;
    return file;
   }
    
 }
 return NULL;
}

