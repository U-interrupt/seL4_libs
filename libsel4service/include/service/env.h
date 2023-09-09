#pragma once

#include <autoconf.h>
#include <sel4/bootinfo.h>
#include <sel4utils/process.h>
#include <simple/simple.h>
#include <vka/object.h>
#include <vka/vka.h>
#include <vspace/vspace.h>

// #define TEST_NORMAL
#define TEST_POLL
// #define TEST_UINTR

#define CUSTOM_IPC_BUFFER_BITS PAGE_BITS_4K
#define CUSTOM_IPC_BUFFER_SIZE (BIT(CUSTOM_IPC_BUFFER_BITS))

struct spinlock {
  uint64_t locked;
};

typedef struct spinlock *spinlock_t;

void initlock(struct spinlock *lk);
void acquire(struct spinlock *lk);
void release(struct spinlock *lk);

struct init_data {
  /* page directory of the process */
  seL4_CPtr page_directory;

  /* root cnode of the process */
  seL4_CPtr root_cnode;

  /* tcb of the process */
  seL4_CPtr tcb;

  /* size of the test processes cspace */
  seL4_Word cspace_size_bits;

  /* range of free slots in the cspace */
  seL4_SlotRegion free_slots;

  /* endpoint of server */
  seL4_CPtr server_ep;

  /* shared ipc buffer between server and this client */
  void *server_buf;

  /* endpoint from client */
  seL4_CPtr client_ep;

  /* shared ipc buffer between this server and client */
  void *client_buf;

#ifdef TEST_POLL
  /* server ipc buffer guard */
  spinlock_t server_lk;

  /* client ipc buffer guard */
  spinlock_t client_lk;
#endif

  /* the number of pages in the stack */
  int stack_pages;

  /* address of the stack */
  void *stack;

  /* only for check */
  unsigned int magic;
};

typedef struct init_data *init_data_t;

struct proc_t {
  /* inner process data */
  sel4utils_process_t proc;

  /* init data frame vaddr shared by root*/
  init_data_t init;

  /* extra cap to the init data frame for mapping into the remote vspace */
  seL4_CPtr init_cap;

  /* remote vaddr of init frame */
  void *init_vaddr;
};

struct root_env {
  /* An initialised vka that may be used by the test. */
  vka_t vka;

  /* virtual memory management interface */
  vspace_t vspace;

  /* abtracts over kernel version and boot environment */
  simple_t simple;

  /* IO ops for devices */
  ps_io_ops_t ops;

  /* Target client using POSIX syscalls */
  struct proc_t app;

  /* xv6 filesystem server */
  struct proc_t fs;

  /* RAM Disk device driver */
  struct proc_t ramdisk;

  /* endpoint between app and fs server */
  vka_object_t app_fs_ep;

  /* shared buffer between app and fs server*/
  void *app_fs_buf;

  /* endpoint between fs server and device driver */
  vka_object_t fs_ram_ep;

  /* shared buffer between fs server and device driver */
  void *fs_ram_buf;
};

typedef struct root_env *root_env_t;