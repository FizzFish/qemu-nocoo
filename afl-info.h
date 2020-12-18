
#define SHM_ENV_VAR         "__AFL_SHM_ID"
#define FORKSRV_FD          198
#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)
#define PRE_SYS_NUM 10
#define FUZZ_SYS_NUM 10

#define STRACE_FD 192
extern unsigned int afl_forksrv_pid;
int check_ratio(void);
void send_syscalls(int num);
void load_pre_syscalls(void);
void record_fuzz_syscall(int num);
