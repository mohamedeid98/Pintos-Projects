#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful,
   -1 if a segfault occurred. */
static int get_user (const uint8_t *uaddr) {
    int result;
    // Check if address is below PHYS_BASE
    if (!is_user_vaddr(uaddr)) {
        return -1;
    }

    // Inline assembly to read memory, handle faults
    asm ("movl $1f, %0; movzbl %1, %0; 1:"
         : "=&a" (result) : "m" (*uaddr));

    return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful,
   false if a segfault occurred. */
static bool put_user (uint8_t *udst, uint8_t byte) {
    int error_code;
    // Check if address is below PHYS_BASE
    if (!is_user_vaddr(udst)) {
        return false;
    }

    // Inline assembly to write memory, handle faults
    asm ("movl $1f, %0; movb %b2, %1; 1:"
         : "=&a" (error_code), "=m" (*udst) : "q" (byte));

    return error_code != -1;
}

static void syscall_handler(struct intr_frame*);

/*Lock for the file system as it isn't thread-friendly*/
struct lock filesys_lock;  



void syscall_init(void) { 
  lock_init(&filesys_lock);    /*Initialize the global lock for the file system*/

  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); 

}

static int handle_write(int fd, const void* buffer, unsigned size) {
  int result;
  int written_bytes = 0;
  unsigned i;

  if(fd == STDOUT_FILENO) {
    for (i = 0 ; i <= size ; i++) {
      result = get_user(buffer + i);
      if (result == -1) { /* Indicates a page fault accured. */
        return -1;
      }
    }
    putbuf(buffer, size); /* Write buffer on console in one call. */
    written_bytes = size;

  } else {
    /* Implement writing to actual file in the file system. */
  }

  return written_bytes;
}

/* Exit a process by printing a statement and freeing all alocated resources. */
void exit(int status) {
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, status);
  process_exit();
}


static void syscall_handler(struct intr_frame* f) {

  uint32_t* args = ((uint32_t*)f->esp);
  if (!args) {
    exit(-1);
  }
  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  
  switch(args[0]) {
    case SYS_EXIT:
      f->eax = args[1];
      exit(args[1]);
      break;
    
    case SYS_WRITE:
      /* Get the user arguments from the user stack. */
      int fd = args[1];
      const void* buffer = (const void*)args[2];
      unsigned size = args[3];

      /* Check if the buffer is within the user space. */
      if (!is_user_vaddr(buffer) || !is_user_vaddr(buffer+size)) {
        f->eax = -1;
        exit(-1);
        break;
      }
      int result = handle_write(fd, buffer, size);
      if(result == -1) {
        f->eax = -1;
        exit(-1);
      } else {
        f->eax = result;
      }
      break;

    case SYS_PRACTICE:
      int num = args[1];
      f->eax = num + 1;
      break;
  }



}
