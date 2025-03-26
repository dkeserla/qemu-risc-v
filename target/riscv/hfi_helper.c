#include "hfi_helper.h"
#include "qemu/log.h"

void helper_hfi_enter(CPURISCVState *env, uint64_t exit_handler)
{
    /* Set HFI sandbox active: status = 1 and record the 64-bit exit handler */
    env->hfi_status = 1;
    env->hfi_exit_pc = exit_handler;
    qemu_log_mask(1, "HFI: Entered sandbox mode; status set to 1, exit_handler=0x%lx\n", exit_handler);
}

void helper_hfi_exit(CPURISCVState *env)
{
    /* Reset HFI sandbox state: status = 0 and clear the exit handler */
    env->hfi_status = 0;
    env->hfi_exit_pc = 0;
    qemu_log_mask(1, "HFI: Exited sandbox mode; status set to 0\n");
}
