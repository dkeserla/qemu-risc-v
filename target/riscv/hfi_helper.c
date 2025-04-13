#include "hfi_helper.h"
#include "qemu/log.h"
#include "trace.h"

void helper_hfi_enter(CPURISCVState *env, uint64_t exit_handler)
{
    /* Set HFI sandbox active: status = 1 and record the 64-bit exit handler */
    env->hfi_status = 1;
    env->hfi_exit_pc = exit_handler;

    qemu_log_mask(LOG_UNIMP, "HFI: Enter sandbox mode, exit_handler=0x%016" PRIx64 "\n", exit_handler);
}

void helper_hfi_exit(CPURISCVState *env)
{
    /* Reset HFI sandbox state: status = 0 and clear the exit handler */
    env->hfi_status = 0;
    env->hfi_exit_pc = 0;
    qemu_log_mask(LOG_UNIMP, "HFI: Exited sandbox mode\n");
}

void helper_hfi_set_region_size(CPURISCVState *env, uint32_t region_number, 
                               uint64_t base, uint64_t mask_or_bound)
{
    if (region_number >= HFI_NUM_DATA_REGIONS) {
        qemu_log_mask(LOG_GUEST_ERROR, "HFI: Invalid region number %d\n", region_number);
        return;
    }

    /* For explicit data regions */
    if (region_number == 0) {
        env->implicit_data_regions[0].prefix = base;
        env->implicit_data_regions[0].mask = mask_or_bound;
        qemu_log_mask(LOG_UNIMP, "HFI: Set region %d size: base=0x%016" PRIx64 
                     ", mask=0x%016" PRIx64 "\n", 
                     region_number, base, mask_or_bound);
    } else if (region_number == 1) {
        /* For implicit data region */
        env->implicit_data_regions[1].prefix = base;
        env->implicit_data_regions[1].mask = mask_or_bound;
        qemu_log_mask(LOG_UNIMP, "HFI: Set implicit data region size: base=0x%016" PRIx64 
                     ", mask=0x%016" PRIx64 "\n", 
                     base, mask_or_bound);
    } else if (region_number == 2) {
        /* For implicit code region */
        env->implicit_code_regions[0].prefix = base;
        env->implicit_code_regions[0].mask = mask_or_bound;
        qemu_log_mask(LOG_UNIMP, "HFI: Set implicit code region size: base=0x%016" PRIx64 
                     ", mask=0x%016" PRIx64 "\n", 
                     base, mask_or_bound);
    }
}

void helper_hfi_set_region_permissions(CPURISCVState *env, uint32_t permission_set, 
                                      uint8_t permission)
{
    if (permission_set >= HFI_NUM_DATA_REGIONS) {
        qemu_log_mask(LOG_GUEST_ERROR, "HFI: Invalid permission set %d\n", permission_set);
        return;
    }

    /* Extract permission bits for the explicit data region (region 1) */
    bool r1_enabled = (permission >> HFI_R1_ENABLED_BIT) & 0x1;
    bool r1_read = (permission >> HFI_R1_READ_BIT) & 0x1;
    bool r1_write = (permission >> HFI_R1_WRITE_BIT) & 0x1;
    bool r1_is_large = (permission >> HFI_R1_IS_LARGE_BIT) & 0x1;

    /* Extract permission bits for the implicit data region (region 2) */
    bool r2_enabled = (permission >> HFI_R2_ENABLED_BIT) & 0x1;
    bool r2_read = (permission >> HFI_R2_READ_BIT) & 0x1;
    bool r2_write = (permission >> HFI_R2_WRITE_BIT) & 0x1;

    /* Extract permission bits for the implicit code region (region 3) */
    bool r3_enabled = (permission >> HFI_R3_ENABLED_BIT) & 0x1;
    bool r3_exec = (permission >> HFI_R3_EXEC_BIT) & 0x1;

    /* Set permissions for regions based on permission_set */
    if (permission_set == 0) {
        /* Configure explicit data region */
        env->implicit_data_regions[0].perm_read = r1_read;
        env->implicit_data_regions[0].perm_write = r1_write;
        
        /* Configure implicit data region */
        env->implicit_data_regions[1].perm_read = r2_read;
        env->implicit_data_regions[1].perm_write = r2_write;
        
        /* Configure implicit code region */
        env->implicit_code_regions[0].perm_exec = r3_exec;
        
        qemu_log_mask(LOG_UNIMP, "HFI: Set permissions for set %d: "
                     "R1[en:%d,r:%d,w:%d,large:%d] "
                     "R2[en:%d,r:%d,w:%d] "
                     "R3[en:%d,x:%d]\n",
                     permission_set,
                     r1_enabled, r1_read, r1_write, r1_is_large,
                     r2_enabled, r2_read, r2_write,
                     r3_enabled, r3_exec);
    }
}
