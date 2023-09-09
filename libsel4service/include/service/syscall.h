#pragma once

#include <sel4/sel4.h>

#include "env.h"

/* Swtich the thread syscalls to remote function call */
void init_syscall_table(seL4_CPtr ep, init_data_t init);

/* Setup init data */
void setup_init_data(init_data_t init);

/* Fetch the nth 32-bit system call argument. */
void argint(int n, int *ip);

/* Retrieve an argument as a pointer. */
void argaddr(int n, uint64_t *ip);

/* Fetch the nth word-sized system call argument as a null-terminated string. */
int argstr(int n, char *buf, int max);

void panic();

#ifdef TEST_POLL
/* This function will hold the lock */
void Wait(seL4_Word *buf);

int Call(seL4_Word *buf);
#endif

#define FS_RET 0

#define FS_READ 3
#define FS_WRITE 4
#define FS_OPEN 5
#define FS_CLOSE 6
#define FS_UNLINK 10
#define FS_LSEEK 19
#define FS_PREAD 180
#define FS_PWRITE 181
#define FS_GETCWD 183
#define FS_LSTAT 196
#define FS_FSTAT 197

#define DISK_RET 0
#define DISK_INIT 1
#define DISK_READ 2
#define DISK_WRITE 3