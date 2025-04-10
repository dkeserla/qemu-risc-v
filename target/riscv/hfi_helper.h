#ifndef RISCV_HFI_HELPER_H
#define RISCV_HFI_HELPER_H

#include "qemu/osdep.h"
#include "cpu.h"

/* 
 * This function takes one 64-bit argument representing the exit handler.
 */
void helper_hfi_enter(CPURISCVState *env, uint64_t exit_handler);

/*
 * Exits the HFI sandbox by resetting the HFI status.
 */
void helper_hfi_exit(CPURISCVState *env);

#endif /* RISCV_HFI_HELPER_H */