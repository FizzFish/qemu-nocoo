#ifndef QEMU_CFG_H
#define QEMU_CFG_H
//#include <stdint.h>
#include "qemu/queue.h"
#include "qemu/typedefs.h"

void graph_add_edge(uint64_t, uint64_t);
typedef struct Branch Branch;

struct Branch
{
    uint64_t pc;
    //X86CPU cpu;
    CPUArchState env;
    //int gray;
    QLIST_ENTRY(Branch) node;
    //void (*save_state)(CPUState * state);
    //void (*load_state)(void);
};

typedef struct BranchList
{
    QLIST_HEAD(, Branch) branches;
} BranchList;

//QLIST_INIT(branch_stack);
void branch_list_init(void);
    
void branch_list_add(CPUArchState * env, uint64_t pc);
    
void branch_remove(Branch *branch);
Branch * branch_list_pop(void);
bool branch_list_empty(void);
void restore_last_branch(CPUX86State *old_env);
#endif
