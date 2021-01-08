/*
  Copyright 2015 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - high-performance binary-only instrumentation
   -----------------------------------------------------------------

   Written by Andrew Griffiths <agriffiths@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   Idea & design very much by Andrew Griffiths.

   This code is a shim patched into the separately-distributed source
   code of QEMU 2.10.0. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.
*/

#include <sys/shm.h>
#include "afl-info.h"

/***************************
 * VARIOUS AUXILIARY STUFF *
 ***************************/

/* A snippet patched into tb_find_slow to inform the parent process that
   we have hit a new block that hasn't been translated yet, and to tell
   it to translate within its own context, too (this avoids translation
   overhead in the next forked-off copy). */

#define CFG 0
#define PRE_STRACE 1
#define FUZZ_STRACE 2
#define NORMAL 3

extern int pre_syscalls[PRE_SYS_NUM];
struct qht_map {
    struct rcu_head rcu;
    struct qht_bucket *buckets;
    size_t n_buckets;
    size_t n_added_buckets;
    size_t n_added_buckets_threshold;
};

#define AFL_QEMU_CPU_SNIPPET1 do { \
    afl_request_tsl(pc, cs_base, flags); \
  } while (0)

/* We use one additional file descriptor to relay "needs translation"
   messages between the child and the fork server. */


/* This is equivalent to afl-as.h: */

static unsigned char *afl_area_ptr;

/* Exported variables populated by the code patched into elfload.c: */

extern abi_ulong afl_entry_point, /* ELF entry point (_start) */
          afl_start_code,  /* .text start pointer      */
          afl_end_code;    /* .text end pointer        */

/* Set in the child process in forkserver mode: */

static unsigned char afl_fork_child;
extern int pre_strace;
extern int fuzz_strace;
extern int fuzz_normal;
extern int do_cfg;

/* Instrumentation ratio: */

static unsigned int afl_inst_rms = MAP_SIZE;

/* Function declarations. */

static bool afl_setup(void);
static void afl_forkserver(CPUState*);
static inline void afl_maybe_log(abi_ulong, abi_ulong);

static void afl_wait_tsl(CPUState*, int);
static void afl_request_tsl(target_ulong, target_ulong, uint64_t);
static void afl_wait_cfg(int fd);
static void afl_wait_syscall(int fd);

/* Data structure passed around by the translate handlers: */

struct afl_tsl {
  target_ulong pc;
  target_ulong cs_base;
  uint64_t flags;
};

/* Some forward decls: */

//TranslationBlock *tb_htable_lookup(CPUState*, target_ulong, target_ulong, uint32_t);
static inline TranslationBlock *tb_find(CPUState*, TranslationBlock*, int);

/*************************
 * ACTUAL IMPLEMENTATION *
 *************************/

/* Set up SHM region and initialize other stuff. */

static bool afl_setup(void) {

  char *id_str = getenv(SHM_ENV_VAR),
       *inst_r = getenv("AFL_INST_RATIO");

  int shm_id;

  if (inst_r) {

    unsigned int r;

    r = atoi(inst_r);

    if (r > 100) r = 100;
    if (!r) r = 1;

    afl_inst_rms = MAP_SIZE * r / 100;

  }

  if (id_str) {

    shm_id = atoi(id_str);
    afl_area_ptr = shmat(shm_id, NULL, 0);

    if (afl_area_ptr == (void*)-1) exit(1);

    /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
       so that the parent doesn't give up on us. */

    if (inst_r) afl_area_ptr[0] = 1;


  } else
      return false;

  if (getenv("AFL_INST_LIBS")) {

    afl_start_code = 0;
    afl_end_code   = (abi_ulong)-1;

  }

  /* pthread_atfork() seems somewhat broken in util/rcu.c, and I'm
     not entirely sure what is the cause. This disables that
     behaviour, and seems to work alright? */

  rcu_disable_atfork();
  return true;

}


/* Fork server logic, invoked once we hit _start. */
extern struct qht cfg_htable;
static void afl_forkserver(CPUState *cpu) {

  static unsigned char tmp[4];
  static int mode = 0;

  if (!afl_area_ptr) return;

  /* Tell the parent that we're alive. If the parent doesn't want
     to talk, assume that we're not running in forkserver mode. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  afl_forksrv_pid = getpid();

  /* All right, let's await orders... */
  while (1) {

    pid_t child_pid;
    int status, t_fd[2];

    /* Whoops, parent dead? */

    if (read(FORKSRV_FD, &mode, 4) != 4) exit(2);
    if (mode == CFG) {
        do_cfg = 1;
    } else if (mode == PRE_STRACE) {
        do_cfg = 0;
        pre_strace = 1;
    } else if (mode == FUZZ_STRACE) {
        pre_strace = 0;
        fuzz_strace = 1;
    } else {
        pre_strace = 0;
        fuzz_normal = 1;
    }

    /* Establish a channel with child to grab translation commands. We'll
       read from t_fd[0], child will write to TSL_FD. */

    if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0) exit(3);
    close(t_fd[1]);

    child_pid = fork();
    if (child_pid < 0) exit(4);

    if (!child_pid) {

      /* Child process. Close descriptors and run free. */

      afl_fork_child = 1;
      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);
      close(t_fd[0]);
      return;

    }

    /* Parent. */

    close(TSL_FD);

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(5);

    /* Collect translation requests until child dies and closes the pipe. */
    if(mode == CFG)
        afl_wait_cfg(t_fd[0]);
    else if(mode == PRE_STRACE)
        afl_wait_syscall(t_fd[0]);
    else
        afl_wait_tsl(cpu, t_fd[0]);

    /* Get and relay exit status to parent. */
    if (waitpid(child_pid, &status, 0) < 0) exit(6);
    if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(7);

  }

}


/* The equivalent of the tuple logging routine from afl-as.h. */
extern int no_exit;

static inline void afl_maybe_log(abi_ulong prev_loc, abi_ulong cur_loc) {

  /* Optimize for cur_loc > afl_end_code, which is the most likely case on
     Linux systems. */
  if (cur_loc > afl_end_code || cur_loc < afl_start_code || !afl_area_ptr)
    return;

  if (no_exit && !cfg_htable_lookup(cur_loc))
    return;

  /* Looks like QEMU always maps to fixed locations, so ASAN is not a
     concern. Phew. But instruction addresses may be aligned. Let's mangle
     the value to get something quasi-uniform. */

  prev_loc  = (prev_loc >> 4) ^ (prev_loc << 8);
  prev_loc &= MAP_SIZE - 1;

  cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 1;

  /* Implement probabilistic instrumentation by looking at scrambled block
     address. This keeps the instrumented locations stable across runs. */

  if (cur_loc >= afl_inst_rms) return;

  afl_area_ptr[cur_loc ^ prev_loc]++;

}


/* This code is invoked whenever QEMU decides that it doesn't have a
   translation of a particular block and needs to compute it. When this happens,
   we tell the parent to mirror the operation, so that the next fork() has a
   cached copy. */

static void afl_request_tsl(target_ulong pc, target_ulong cb, uint64_t flags) {

  struct afl_tsl t;

  if (!afl_fork_child) return;
  if (pc > afl_end_code || pc < afl_start_code)
      return;

  t.pc      = pc;
  t.cs_base = cb;
  t.flags   = flags;

  if (write(TSL_FD, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
    return;

}

static void afl_mark_cfg(target_ulong pc) {
  CFGPoint cfg = {pc};
  //printf("%s write %lx\n", __func__, pc);
  if (write(TSL_FD, &cfg, sizeof(CFGPoint)) != sizeof(CFGPoint))
      return;

}

static void afl_wait_cfg(int fd) {

  CFGPoint cfg;

  while (1) {

    /* Broken pipe means it's time to return to the fork server routine. */
    if (read(fd, &cfg, sizeof(CFGPoint)) != sizeof(CFGPoint))
      break;

    if (!cfg_htable_lookup(cfg.pc)) {
    //printf("htable add %lx\n", cfg.pc);
        cfg_htable_add(cfg.pc);
    }

  }

  close(fd);
}

static void afl_wait_syscall(int fd) {

  int num;
  int syscall_num = 0;

  int tmp_syscalls[PRE_SYS_NUM];
  int i, p = 0;
  while (1) {

    //if (read(fd, &num, sizeof(int)) != sizeof(int))
    if (read(fd, &num, 4) != 4)
      break;
    if(num == 202)
        continue;
    tmp_syscalls[p] = num;
    p = (p + 1) % PRE_SYS_NUM;
    syscall_num++;

  }
    for(i=0;i<PRE_SYS_NUM;i++) {
        pre_syscalls[i] = tmp_syscalls[(i+p)%PRE_SYS_NUM];
        //printf("syscall[%d]=%d ", i, pre_syscalls[i]);
    }
    //printf("\nqemu recv %d syscalls\n", syscall_num);

  close(fd);
}

/* This is the other side of the same channel. Since timeouts are handled by
   afl-fuzz simply killing the child, we can just wait until the pipe breaks. */

static void afl_wait_tsl(CPUState *cpu, int fd) {

  struct afl_tsl t;
  TranslationBlock *tb;

  while (1) {

    /* Broken pipe means it's time to return to the fork server routine. */
    if (read(fd, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
      break;

    tb = tb_htable_lookup(cpu, t.pc, t.cs_base, t.flags);

    if(!tb) {
      mmap_lock();
      tb_lock();
      tb_gen_code(cpu, t.pc, t.cs_base, t.flags, 0);
      mmap_unlock();
      tb_unlock();
    }

  }

  close(fd);

}
