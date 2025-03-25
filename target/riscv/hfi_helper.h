#ifndef RISCV_HFI_HELPER_H
#define RISCV_HFI_HELPER_H

#include "cpu.h"
#include <stdint.h>

/* 
 * This function takes one 64-bit argument representing the exit handler.
 */
void riscv_hfi_enter(RISCVCPU *cpu, uint64_t exit_handler);

/*
 * Exits the HFI sandbox by resetting the HFI status.
 */
void riscv_hfi_exit(RISCVCPU *cpu);

#endif /* RISCV_HFI_HELPER_H */