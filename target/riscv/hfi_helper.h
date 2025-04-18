#ifndef RISCV_HFI_HELPER_H
#define RISCV_HFI_HELPER_H

#include "qemu/osdep.h"
#include "cpu.h"

/* 
 * This function takes one 64-bit argument representing the exit handler.
 * The region_type parameter specifies the type of region to use:
 *   0 = no sandboxing
 *   1 = explicit regions
 *   2 = implicit regions
 *   (other values reserved for future use)
 */
void helper_hfi_enter(CPURISCVState *env, uint32_t region_type, uint64_t exit_handler);

/*
 * Exits the HFI sandbox by resetting the HFI status.
 */
void helper_hfi_exit(CPURISCVState *env);

/*
 * Set HFI region size for a specific region number
 * region_number: specifies which region to configure
 * base: base address of the region
 * mask_or_bound: size mask or bound of the region
 */
void helper_hfi_set_region_size(CPURISCVState *env, uint32_t region_number, uint64_t base, uint64_t mask_or_bound);

/*
 * Set HFI region permissions for a specific permission set
 * region_number: which region to configure permissions for
 * permission: bit vector containing permission settings as:
 *   r1_enabled:r1_read:r1_write:r1_is_large:
 *   r2_enabled:r2_read:r2_write:
 *   r3_enabled:r3_exec
 */
void helper_hfi_set_region_permissions(CPURISCVState *env, uint32_t region_number, uint32_t permission);

#endif /* RISCV_HFI_HELPER_H */