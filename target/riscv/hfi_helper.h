#ifndef RISCV_HFI_HELPER_H
#define RISCV_HFI_HELPER_H

#include "qemu/osdep.h"
#include "cpu.h"

/* 
 * This function takes one 64-bit argument representing the exit handler.
 */
void riscv_hfi_enter(uint64_t exit_handler);

/*
 * Exits the HFI sandbox by resetting the HFI status.
 */
void riscv_hfi_exit(void);

#endif /* RISCV_HFI_HELPER_H */