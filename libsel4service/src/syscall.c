#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bits/syscall.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <sel4/sel4.h>

#include <arch_stdio.h>
#include <muslcsys/vsyscall.h>

#include "service/env.h"
#include "service/syscall.h"

#define min(a, b) ((a) < (b) ? (a) : (b))

static seL4_CPtr fs_ep = seL4_CapNull;

static init_data_t init_data = NULL;

static int uintr_index = 0;

void initlock(struct spinlock *lk) { lk->locked = 0; }

void acquire(struct spinlock *lk) {
  // On RISC-V, sync_lock_test_and_set turns into an atomic swap:
  //   a5 = 1
  //   s1 = &lk->locked
  //   amoswap.w.aq a5, a5, (s1)
  while (__sync_lock_test_and_set(&lk->locked, 1) != 0)
    ;

  // Tell the C compiler and the processor to not move loads or stores
  // past this point, to ensure that the critical section's memory
  // references happen strictly after the lock is acquired.
  // On RISC-V, this emits a fence instruction.
  __sync_synchronize();
}

void release(struct spinlock *lk) {
  // Tell the C compiler and the CPU to not move loads or stores
  // past this point, to ensure that all the stores in the critical
  // section are visible to other CPUs before the lock is released,
  // and that loads in the critical section occur strictly before
  // the lock is released.
  // On RISC-V, this emits a fence instruction.
  __sync_synchronize();

  // Release the lock, equivalent to lk->locked = 0.
  // This code doesn't use a C assignment, since the C standard
  // implies that an assignment might be implemented with
  // multiple store instructions.
  // On RISC-V, sync_lock_release turns into an atomic swap:
  //   s1 = &lk->locked
  //   amoswap.w zero, zero, (s1)
  __sync_lock_release(&lk->locked);
}

#ifdef TEST_NORMAL
void argint(int n, int *ip) { *ip = seL4_GetMR(n); }
void argaddr(int n, uint64_t *ip) { *ip = seL4_GetMR(n); }
#elif defined(TEST_POLL) || defined(TEST_UINTR)
void argint(int n, int *ip) {
  seL4_Word *buf = init_data->client_buf;
  *ip = buf[n + 1];
}
void argaddr(int n, uint64_t *ip) {
  seL4_Word *buf = init_data->client_buf;
  *ip = buf[n + 1];
}
#endif

/* Fetch the nth word-sized system call argument as a null-terminated string. */
int argstr(int n, char *buf, int max) {
  uint64_t addr;
  argaddr(n, &addr);
  strcpy(buf, (char *)addr);
  return strlen(buf);
}

#ifdef TEST_POLL
/* This function will hold the lock */
void Wait(seL4_Word *buf) {
  while (1) {
    acquire(init_data->server_lk);
    if (buf[0]) {
      release(init_data->server_lk);
      continue;
    } else
      break;
  }
}

int Call(seL4_Word *buf) {
  Wait(buf);
  int ret = buf[1];
  release(init_data->server_lk);
  return ret;
}
#endif

#ifdef TEST_UINTR
void Call(void) {
  seL4_Word badge;
  seL4_UintrSend(uintr_index);
  while (1) {
    seL4_UintrNBRecv(&badge);
    if (badge)
      break;
  }
}
#endif

static long sel4service_unimp(va_list ap) { return 0; }

static long sel4service_open_imp(const char *pathname, int flags, mode_t mode) {
#ifdef TEST_NORMAL
  seL4_MessageInfo_t info = seL4_MessageInfo_new(FS_OPEN, 0, 0, 3);
  strcpy(init_data->server_buf, pathname);
  seL4_SetMR(0, (seL4_Word)init_data->server_buf);
  seL4_SetMR(1, flags);
  seL4_SetMR(2, mode);
  info = seL4_Call(fs_ep, info);
  return seL4_GetMR(0);
#elif defined(TEST_POLL)
  seL4_Word *buf = init_data->server_buf;
  acquire(init_data->server_lk);
  buf[0] = FS_OPEN;
  buf[1] = (seL4_Word)&buf[4];
  buf[2] = flags;
  buf[3] = mode;
  strcpy((char *)&buf[4], pathname);
  release(init_data->server_lk);
  return Call(buf);
#elif defined(TEST_UINTR)
  seL4_Word *buf = init_data->server_buf;
  buf[0] = FS_OPEN;
  buf[1] = (seL4_Word)&buf[4];
  buf[2] = flags;
  buf[3] = mode;
  strcpy((char *)&buf[4], pathname);
  Call();
  return buf[1];
#endif
}

static long sel4service_open(va_list ap) {
  const char *pathname = va_arg(ap, const char *);
  int flags = va_arg(ap, int);
  mode_t mode = va_arg(ap, mode_t);

  return sel4service_open_imp(pathname, flags, mode);
}

static long sel4service_close(va_list ap) {
  int fd = va_arg(ap, int);
#ifdef TEST_NORMAL
  seL4_MessageInfo_t info = seL4_MessageInfo_new(FS_CLOSE, 0, 0, 1);
  seL4_SetMR(0, fd);
  info = seL4_Call(fs_ep, info);
  return seL4_GetMR(0);
#elif defined(TEST_POLL)
  seL4_Word *buf = init_data->server_buf;
  acquire(init_data->server_lk);
  buf[0] = FS_CLOSE;
  buf[1] = fd;
  release(init_data->server_lk);
  return Call(buf);
#elif defined(TEST_UINTR)
  seL4_Word *buf = init_data->server_buf;
  buf[0] = FS_CLOSE;
  buf[1] = fd;
  Call();
  return buf[1];
#endif
}

int __plat_getchar(void);
static size_t read_buf(void *data, size_t count) {
  char *buf = data;
  for (int i = 0; i < count; i++) {
    buf[i] = __plat_getchar();
  }
  return count;
}

static long sel4service_unlink(va_list ap) {
  const char *pathname = va_arg(ap, const char *);
#ifdef TEST_NORMAL
  seL4_MessageInfo_t info = seL4_MessageInfo_new(FS_UNLINK, 0, 0, 1);
  strcpy(init_data->server_buf, pathname);
  seL4_SetMR(0, (seL4_Word)init_data->server_buf);
  info = seL4_Call(fs_ep, info);
  return seL4_GetMR(0);
#elif defined(TEST_POLL)
  seL4_Word *buf = init_data->server_buf;
  acquire(init_data->server_lk);
  buf[0] = FS_UNLINK;
  buf[1] = (seL4_Word)&buf[2];
  strcpy((char *)&buf[2], pathname);
  release(init_data->server_lk);
  return Call(buf);
#elif defined(TEST_UINTR)
  seL4_Word *buf = init_data->server_buf;
  buf[0] = FS_UNLINK;
  buf[1] = (seL4_Word)&buf[2];
  strcpy((char *)&buf[2], pathname);
  Call();
  return buf[1];
#endif
}

static long sel4service_rw_imp(int fd, void *buf, size_t size, off_t off,
                               int label, int write) {
  int n = (size + CUSTOM_IPC_BUFFER_SIZE - 1) / CUSTOM_IPC_BUFFER_SIZE;
  if (!n)
    return 0;
  int i;
  size_t sum = 0;
  for (i = 0; i < n; i++) {
    size_t count =
        min(size - i * CUSTOM_IPC_BUFFER_SIZE, CUSTOM_IPC_BUFFER_SIZE);
#ifdef TEST_NORMAL
    seL4_MessageInfo_t info = seL4_MessageInfo_new(label, 0, 0, 4);
    seL4_SetMR(0, fd);
    seL4_SetMR(1, (seL4_Word)init_data->server_buf);
    seL4_SetMR(2, count);
    seL4_SetMR(3, off);
    if (write)
      memmove(init_data->server_buf, buf + sum, count);
    info = seL4_Call(fs_ep, info);
    if (!write)
      memmove(buf + sum, init_data->server_buf, count);
    sum += seL4_GetMR(0);
#elif defined(TEST_POLL)
    seL4_Word *server_buf = init_data->server_buf;
    acquire(init_data->server_lk);
    server_buf[0] = label;
    server_buf[1] = fd;
    server_buf[2] = (seL4_Word)&server_buf[5];
    server_buf[3] = count;
    server_buf[4] = off;
    if (write)
      memmove((void *)&server_buf[5], buf + sum, count);
    release(init_data->server_lk);
    Wait(server_buf);
    if (!write)
      memmove(buf + sum, (void *)&server_buf[5], count);
    sum += server_buf[1];
    release(init_data->server_lk);
#elif defined(TEST_UINTR)
    seL4_Word *server_buf = init_data->server_buf;
    server_buf[0] = label;
    server_buf[1] = fd;
    server_buf[2] = (seL4_Word)&server_buf[5];
    server_buf[3] = count;
    server_buf[4] = off;
    if (write)
      memmove((void *)&server_buf[5], buf + sum, count);
    Call();
    if (!write)
      memmove(buf + sum, (void *)&server_buf[5], count);
    sum += server_buf[1];
#endif
  }
  return sum;
}

static long sel4service_readv(va_list ap) {
  int fd = va_arg(ap, int);
  struct iovec *iov = va_arg(ap, struct iovec *);
  int iovcnt = va_arg(ap, int);
  long long sum = 0;
  ssize_t ret = 0;

  /* The iovcnt argument is valid if greater than 0 and less than or equal to
   * IOV_MAX. */
  if (iovcnt <= 0 || iovcnt > IOV_MAX) {
    return -EINVAL;
  }

  /* The sum of iov_len is valid if less than or equal to SSIZE_MAX i.e. cannot
     overflow a ssize_t. */
  for (int i = 0; i < iovcnt; i++) {
    sum += (long long)iov[i].iov_len;
    if (sum > SSIZE_MAX) {
      return -EINVAL;
    }
  }

  /* If all the iov_len members in the array are 0, return 0. */
  if (!sum) {
    return 0;
  }

  /* Write the buffer to console if the fd is for stdout or stderr. */
  if (fd == STDIN_FILENO) {
    for (int i = 0; i < iovcnt; i++) {
      ret += read_buf(iov[i].iov_base, iov[i].iov_len);
    }
  } else {
    for (int i = 0; i < iovcnt; i++) {
      ret += sel4service_rw_imp(fd, iov[i].iov_base, iov[i].iov_len, 0, FS_READ,
                                0);
    }
  }

  return ret;
}

static long sel4service_read(va_list ap) {
  int fd = va_arg(ap, int);
  void *buf = va_arg(ap, void *);
  size_t count = va_arg(ap, size_t);
  return sel4service_rw_imp(fd, buf, count, 0, FS_READ, 0);
}

static long sel4service_pread64(va_list ap) {
  int fd = va_arg(ap, int);
  void *buf = va_arg(ap, void *);
  size_t count = va_arg(ap, size_t);
  off_t off = va_arg(ap, off_t);
  // printf("pread64 %d %p %lu %lu\n", fd, buf, count, off);
  return sel4service_rw_imp(fd, buf, count, off, FS_PREAD, 0);
}

void __plat_putchar(int c);
static size_t write_buf(void *data, size_t count) {
  char *buf = data;
  for (int i = 0; i < count; i++) {
    __plat_putchar(buf[i]);
  }
  return count;
}

void panic(char *s) {
  char *ptr;
  __plat_putchar('!');
  for (ptr = s; *ptr != '\0'; ptr++) {
    __plat_putchar(*ptr);
  }
  __plat_putchar('\n');

  seL4_TCB_Suspend(init_data->tcb);
}

static long sel4service_writev(va_list ap) {
  int fd = va_arg(ap, int);
  struct iovec *iov = va_arg(ap, struct iovec *);
  int iovcnt = va_arg(ap, int);

  long long sum = 0;
  ssize_t ret = 0;

  /* The iovcnt argument is valid if greater than 0 and less than or equal to
   * IOV_MAX. */
  if (iovcnt <= 0 || iovcnt > IOV_MAX) {
    return -EINVAL;
  }

  /* The sum of iov_len is valid if less than or equal to SSIZE_MAX i.e. cannot
     overflow a ssize_t. */
  for (int i = 0; i < iovcnt; i++) {
    sum += (long long)iov[i].iov_len;
    if (sum > SSIZE_MAX) {
      return -EINVAL;
    }
  }

  /* If all the iov_len members in the array are 0, return 0. */
  if (!sum) {
    return 0;
  }

  /* Write the buffer to console if the fd is for stdout or stderr. */
  if (fd == STDOUT_FILENO || fd == STDERR_FILENO) {
    for (int i = 0; i < iovcnt; i++) {
      ret += write_buf(iov[i].iov_base, iov[i].iov_len);
    }
  } else {
    for (int i = 0; i < iovcnt; i++) {
      ret += sel4service_rw_imp(fd, iov[i].iov_base, iov[i].iov_len, 0,
                                FS_WRITE, 1);
    }
  }

  return ret;
}

static long sel4service_write(va_list ap) {
  int fd = va_arg(ap, int);
  void *buf = va_arg(ap, void *);
  size_t count = va_arg(ap, size_t);
  return sel4service_rw_imp(fd, buf, count, 0, FS_WRITE, 1);
}

static long sel4service_pwrite64(va_list ap) {
  int fd = va_arg(ap, int);
  void *buf = va_arg(ap, void *);
  size_t count = va_arg(ap, size_t);
  off_t off = va_arg(ap, off_t);
  // printf("pwrite64 %d %p %lu %lu\n", fd, buf, count, off);
  return sel4service_rw_imp(fd, buf, count, off, FS_PWRITE, 1);
}

static long sel4service_fcntl64(va_list ap) {
  int fd = va_arg(ap, int);
  int cmd = va_arg(ap, int);
  // printf("fcntl fd=%d ", fd);

  /* we just set the lock manually */
  if (cmd == F_GETLK) {
    struct flock *lock = va_arg(ap, struct flock *);
    // printf("GETLK %d %d %lx %lx %d", lock->l_type, lock->l_whence,
    //        lock->l_start, lock->l_len, lock->l_pid);
    lock->l_type = F_UNLCK;
  } else if (cmd == F_SETLK) {
    struct flock *lock = va_arg(ap, struct flock *);
    // printf("SETLK %d %d %lx %lx %d", lock->l_type, lock->l_whence,
    //        lock->l_start, lock->l_len, lock->l_pid);
  } else if (cmd == F_SETFD) {
    int flags = va_arg(ap, int);
    // printf("SETFD %d", flags);
  }

  // printf("\n");
  return 0;
}

static long sel4service_fstat_imp(int fd, struct stat *stat) {
#ifdef TEST_NORMAL
  seL4_MessageInfo_t info = seL4_MessageInfo_new(FS_FSTAT, 0, 0, 3);
  seL4_SetMR(0, fd);
  seL4_SetMR(1, (seL4_Word)init_data->server_buf);
  info = seL4_Call(fs_ep, info);
  memmove(stat, init_data->server_buf, sizeof(struct stat));
  stat->st_mode |= 0777;
  stat->st_blksize = 1024;
  // printf("fstat %o 0x%lx %lu\n", stat->st_mode, stat->st_size, stat->st_ino);
  return seL4_GetMR(0);
#elif defined(TEST_POLL)
  seL4_Word *buf = init_data->server_buf;
  acquire(init_data->server_lk);
  buf[0] = FS_FSTAT;
  buf[1] = fd;
  buf[2] = (seL4_Word)&buf[3];
  release(init_data->server_lk);
  Wait(buf);
  memmove(stat, (void *)&buf[3], sizeof(struct stat));
  int ret = buf[1];
  release(init_data->server_lk);
  stat->st_mode |= 0777;
  stat->st_blksize = 1024;
  return ret;
#elif defined(TEST_UINTR)
  seL4_Word *buf = init_data->server_buf;
  buf[0] = FS_FSTAT;
  buf[1] = fd;
  buf[2] = (seL4_Word)&buf[3];
  Call();
  memmove(stat, (void *)&buf[3], sizeof(struct stat));
  stat->st_mode |= 0777;
  stat->st_blksize = 1024;
  return buf[1];
#endif
}

static long sel4service_fstat64(va_list ap) {
  int fd = va_arg(ap, int);
  struct stat *stat = va_arg(ap, void *);
  return sel4service_fstat_imp(fd, stat);
}

static long sel4service_getcwd(va_list ap) {
  char *path = va_arg(ap, void *);
  size_t size = va_arg(ap, size_t);
#ifdef TEST_NORMAL
  seL4_MessageInfo_t info = seL4_MessageInfo_new(FS_GETCWD, 0, 0, 2);
  seL4_SetMR(0, (seL4_Word)init_data->server_buf);
  info = seL4_Call(fs_ep, info);
  strcpy(path, init_data->server_buf);
  return seL4_GetMR(0);
#elif defined(TEST_POLL)
  seL4_Word *buf = init_data->server_buf;
  acquire(init_data->server_lk);
  buf[0] = FS_GETCWD;
  buf[1] = (seL4_Word)&buf[3];
  buf[2] = size;
  release(init_data->server_lk);
  Wait(buf);
  strcpy(path, (char *)&buf[3]);
  int ret = buf[1];
  release(init_data->server_lk);
  return ret;
#elif defined (TEST_UINTR)
  seL4_Word *buf = init_data->server_buf;
  buf[0] = FS_GETCWD;
  buf[1] = (seL4_Word)&buf[3];
  buf[2] = size;
  Call();
  strcpy(path, (char *)&buf[3]);
  return buf[1];
#endif
}

static long sel4service_lstat64(va_list ap) {
  char *path = va_arg(ap, void *);
  struct stat *stat = va_arg(ap, void *);
#ifdef TEST_NORMAL
  seL4_MessageInfo_t info = seL4_MessageInfo_new(FS_LSTAT, 0, 0, 2);
  strcpy(init_data->server_buf, path);
  seL4_SetMR(0, (seL4_Word)init_data->server_buf);
  seL4_SetMR(1, (seL4_Word)init_data->server_buf);
  info = seL4_Call(fs_ep, info);
  memmove(stat, init_data->server_buf, sizeof(struct stat));
  stat->st_mode |= 0777;
  stat->st_blksize = 1024;
  return seL4_GetMR(0);
#elif defined(TEST_POLL)
  seL4_Word *buf = init_data->server_buf;
  acquire(init_data->server_lk);
  buf[0] = FS_LSTAT;
  buf[1] = (seL4_Word)&buf[3];
  buf[2] = (seL4_Word)&buf[3];
  strcpy((char *)&buf[3], path);
  release(init_data->server_lk);
  Wait(buf);
  memmove(stat, &buf[3], sizeof(struct stat));
  stat->st_mode |= 0777;
  stat->st_blksize = 1024;
  int ret = buf[1];
  release(init_data->server_lk);
  return ret;
#elif defined(TEST_UINTR)
  seL4_Word *buf = init_data->server_buf;
  buf[0] = FS_LSTAT;
  buf[1] = (seL4_Word)&buf[3];
  buf[2] = (seL4_Word)&buf[3];
  strcpy((char *)&buf[3], path);
  Call();
  memmove(stat, &buf[3], sizeof(struct stat));
  stat->st_mode |= 0777;
  stat->st_blksize = 1024;
  return buf[1];
#endif
}

static long sel4service_lseek(va_list ap) {
  int fd = va_arg(ap, int);
  off_t off = va_arg(ap, off_t);
  int whence = va_arg(ap, int);
#ifdef TEST_NORMAL
  seL4_MessageInfo_t info = seL4_MessageInfo_new(FS_LSEEK, 0, 0, 3);
  seL4_SetMR(0, fd);
  seL4_SetMR(1, off);
  seL4_SetMR(2, whence);
  info = seL4_Call(fs_ep, info);
  return seL4_GetMR(0);
#elif defined(TEST_POLL)
  seL4_Word *buf = init_data->server_buf;
  acquire(init_data->server_lk);
  buf[0] = FS_LSEEK;
  buf[1] = fd;
  buf[2] = off;
  buf[3] = whence;
  release(init_data->server_lk);
  return Call(buf);
#elif defined (TEST_UINTR)
  seL4_Word *buf = init_data->server_buf;
  buf[0] = FS_LSEEK;
  buf[1] = fd;
  buf[2] = off;
  buf[3] = whence;
  return buf[1];
#endif
}

#ifdef __ASSEMBLER__
#define __ASM_STR(x) x
#else
#define __ASM_STR(x) #x
#endif

#define csr_read(csr)                                                          \
  ({                                                                           \
    register unsigned long __v;                                                \
    __asm__ __volatile__("csrr %0, " __ASM_STR(csr) : "=r"(__v) : : "memory"); \
    __v;                                                                       \
  })

static inline uint64_t get_time64(void) { return csr_read(0xc01); }

#define TIMEBASE_FREQ 10000000
#define USEC_PER_SEC 1000000
#define NSEC_PER_SEC 1000000000

static long sel4service_gettimeofday(va_list ap) {
  struct timeval *v = va_arg(ap, struct timeval *);
  uint64_t time = get_time64();
  v->tv_sec = time / TIMEBASE_FREQ;
  v->tv_usec = time * USEC_PER_SEC / TIMEBASE_FREQ - v->tv_sec * USEC_PER_SEC;
  return 0;
}

static long sel4service_gettime(va_list ap) {
  clockid_t id = va_arg(ap, clockid_t);
  struct timespec *v = va_arg(ap, struct timespec *);
  uint64_t time = get_time64();
  v->tv_sec = time / TIMEBASE_FREQ;
  v->tv_nsec = time * NSEC_PER_SEC / TIMEBASE_FREQ - v->tv_sec * NSEC_PER_SEC;
  return 0;
}

static void syscall_trace(long sysnum) {
  char buf[100];
  int i;
  sprintf(buf, "[libsel4service: syscall %ld]\n", sysnum);
  for (i = 0; buf[i]; i++) {
    seL4_DebugPutChar(buf[i]);
  }
}

void setup_init_data(init_data_t init) { init_data = init; }

void setup_server_ep(seL4_CPtr ep) { fs_ep = ep; }

void setup_server_uintr(seL4_CPtr uintr) {
  seL4_RISCV_Uintr_RegisterSender_t res =
      seL4_RISCV_Uintr_RegisterSender(uintr);
  ZF_LOGF_IF(res.error, "Failed to register uintr");
  uintr_index = res.index;
}

void init_syscall_table(void) {
  sel4muslcsys_register_stdio_write_fn(write_buf);
  muslcsys_register_syscall_trace_fn(syscall_trace);

  muslcsys_install_syscall(__NR_readv, sel4service_readv);
  muslcsys_install_syscall(__NR_read, sel4service_read);
  muslcsys_install_syscall(__NR_writev, sel4service_writev);
  muslcsys_install_syscall(__NR_write, sel4service_write);
  muslcsys_install_syscall(__NR_open, sel4service_open);
  muslcsys_install_syscall(__NR_close, sel4service_close);
  muslcsys_install_syscall(__NR_fcntl64, sel4service_fcntl64);
  muslcsys_install_syscall(__NR_getdents64, sel4service_unimp);
  muslcsys_install_syscall(__NR_clock_gettime, sel4service_gettime);
  muslcsys_install_syscall(__NR_gettimeofday, sel4service_gettimeofday);
  muslcsys_install_syscall(__NR_fstat64, sel4service_fstat64);
  muslcsys_install_syscall(__NR_getcwd, sel4service_getcwd);
  muslcsys_install_syscall(__NR_lstat64, sel4service_lstat64);
  muslcsys_install_syscall(__NR_stat64, sel4service_lstat64);
  muslcsys_install_syscall(__NR_lseek, sel4service_lseek);
  muslcsys_install_syscall(__NR_pread64, sel4service_pread64);
  muslcsys_install_syscall(__NR_pwrite64, sel4service_pwrite64);
  muslcsys_install_syscall(__NR_geteuid32, sel4service_unimp);
  muslcsys_install_syscall(__NR_fchown32, sel4service_unimp);
  muslcsys_install_syscall(__NR_nanosleep, sel4service_unimp);
  muslcsys_install_syscall(__NR_unlink, sel4service_unlink);
  muslcsys_install_syscall(__NR_getpid, sel4service_unimp);
  muslcsys_install_syscall(__NR_fsync, sel4service_unimp);
  muslcsys_install_syscall(__NR_ftruncate64, sel4service_unimp);
}
