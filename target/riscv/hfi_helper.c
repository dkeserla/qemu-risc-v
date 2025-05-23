#include "hfi_helper.h"
#include "qemu/log.h"
#include "trace.h"

void helper_hfi_log(CPURISCVState *env, uint64_t addr, uint64_t prefix, uint64_t mask,
                    uint64_t region, uint64_t matched, uint64_t region_type) {
    const char *type_str = "(unknown)";
    switch (region_type) {
        case 0: type_str = "explicit"; break;
        case 1: type_str = "data";     break;
        case 2: type_str = "internal"; break;
    }

    qemu_log_mask(LOG_UNIMP,
        "HFI: [%s region %d] addr=0x%016" PRIx64 " & mask=0x%016" PRIx64
        " → 0x%016" PRIx64 ", expecting prefix=0x%016" PRIx64 " → match=%d\n",
        type_str, region, addr, mask, addr & mask, prefix, matched);
}

void helper_hfi_trap_log(CPURISCVState *env, uint64_t access_type, uint64_t region_type) {
    const char *atype = (access_type == 0) ? "read" : "write";
    const char *rtype = "(unknown)";

    switch (region_type) {
        case 0: rtype = "explicit"; break;
        case 1: rtype = "data";     break;
        case 2: rtype = "internal"; break;
    }

    qemu_log_mask(LOG_UNIMP, "HFI: trap → no %s permission matched in %s region\n", atype, rtype);
}


void helper_hfi_enter(CPURISCVState *env, uint64_t region_type, uint64_t exit_handler)
{
    /* Set HFI sandbox active: status = 1 and record the 64-bit exit handler */
    env->hfi_status = 1;
    env->hfi_exit_pc = exit_handler;
    env->hfi_region_type = region_type;

    qemu_log_mask(LOG_UNIMP, "HFI: Enter sandbox mode, region_type=%llu, exit_handler=0x%016" PRIx64 "\n", 
                 region_type, exit_handler);
}

void helper_hfi_exit(CPURISCVState *env)
{
    /* Reset HFI sandbox state: status = 0 and clear the exit handler */
    env->hfi_status = 0;

    // might want to reenter with same state
    // env->hfi_exit_pc = 0;
    // env->hfi_region_type = 0; 
    qemu_log_mask(LOG_UNIMP, "HFI: Exited sandbox mode\n");
}

void helper_hfi_set_region_size(CPURISCVState *env, uint64_t region_number, 
                               uint64_t base, uint64_t mask_or_bound)
{
    /* Check for explicit data regions: 0 <= region_number < HFI_NUM_DATA_REGIONS */
    if (region_number < HFI_NUM_DATA_REGIONS) {
        /* 
         * TODO: Explicit data regions are not yet implemented.
         */
        qemu_log_mask(LOG_UNIMP, "HFI: Explicit data region %d not yet implemented\n", 
                     region_number);
    } 
    /* Check for implicit data regions: HFI_NUM_DATA_REGIONS <= region_number < 2*HFI_NUM_DATA_REGIONS */
    else if (region_number < 2 * HFI_NUM_DATA_REGIONS) {
        /* Calculate index into implicit_data_regions array */
        uint64_t idx = region_number - HFI_NUM_DATA_REGIONS;
        
        /* For implicit data region */
        env->implicit_data_regions[idx].prefix = base;
        env->implicit_data_regions[idx].mask = mask_or_bound;
        qemu_log_mask(LOG_UNIMP, "HFI: Set implicit data region %d size: base=0x%016" PRIx64 
                     ", mask=0x%016" PRIx64 "\n", 
                     idx, base, mask_or_bound);
    } 
    /* Check for implicit code regions: 2*HFI_NUM_DATA_REGIONS <= region_number < 2*HFI_NUM_DATA_REGIONS+HFI_NUM_CODE_REGIONS */
    else if (region_number < 2 * HFI_NUM_DATA_REGIONS + HFI_NUM_CODE_REGIONS) {
        /* Calculate index into implicit_code_regions array */
        uint64_t idx = region_number - 2 * HFI_NUM_DATA_REGIONS;
        
        /* For implicit code region */
        env->implicit_code_regions[idx].prefix = base;
        env->implicit_code_regions[idx].mask = mask_or_bound;
        qemu_log_mask(LOG_UNIMP, "HFI: Set implicit code region %d size: base=0x%016" PRIx64 
                     ", mask=0x%016" PRIx64 "\n", 
                     idx, base, mask_or_bound);
    } else {
        qemu_log_mask(LOG_GUEST_ERROR, "HFI: Invalid region number %d\n", region_number);
    }
}

void helper_hfi_set_region_permissions(CPURISCVState *env, uint64_t region_number, 
                                      uint64_t permission)
{
    /* Check for explicit data regions: 0 <= region_number < HFI_NUM_DATA_REGIONS */
    if (region_number < HFI_NUM_DATA_REGIONS) {
        /* Extract permission bits for explicit data regions (R1) */
        bool enabled = (permission >> HFI_R1_ENABLED_BIT) & 0x1;
        bool read = (permission >> HFI_R1_READ_BIT) & 0x1;
        bool write = (permission >> HFI_R1_WRITE_BIT) & 0x1;
        bool is_large = (permission >> HFI_R1_IS_LARGE_BIT) & 0x1;
        
        /* 
         * TODO: Explicit data regions are not yet implemented.
         */
        qemu_log_mask(LOG_UNIMP, "HFI: Explicit data region %d permissions not yet implemented\n"
                     "[en:%d, r:%d, w:%d, large:%d]\n",
                     region_number, enabled, read, write, is_large);
    } 
    /* Check for implicit data regions: HFI_NUM_DATA_REGIONS <= region_number < 2*HFI_NUM_DATA_REGIONS */
    else if (region_number < 2 * HFI_NUM_DATA_REGIONS) {
        /* Extract permission bits for implicit data regions (R2) */
        bool enabled = (permission >> HFI_R2_ENABLED_BIT) & 0x1;
        bool read = (permission >> HFI_R2_READ_BIT) & 0x1;
        bool write = (permission >> HFI_R2_WRITE_BIT) & 0x1;
        
        /* Calculate index into implicit_data_regions array */
        uint32_t idx = region_number - HFI_NUM_DATA_REGIONS;
        
        /* Configure implicit data region */
        env->implicit_data_regions[idx].perm_read = read;
        env->implicit_data_regions[idx].perm_write = write;
        env->implicit_data_regions[idx].enabled = enabled;
        qemu_log_mask(LOG_UNIMP, "HFI: Set permissions for implicit data region %d: "
                     "en:%d, r:%d, w:%d\n",
                     idx, enabled, read, write);
    } 
    /* Check for implicit code regions: 2*HFI_NUM_DATA_REGIONS <= region_number < 2*HFI_NUM_DATA_REGIONS+HFI_NUM_CODE_REGIONS */
    else if (region_number < 2 * HFI_NUM_DATA_REGIONS + HFI_NUM_CODE_REGIONS) {
        /* Extract permission bits for implicit code regions (R3) */
        bool enabled = (permission >> HFI_R3_ENABLED_BIT) & 0x1;
        bool exec = (permission >> HFI_R3_EXEC_BIT) & 0x1;
        
        /* Calculate index into implicit_code_regions array */
        uint64_t idx = region_number - 2 * HFI_NUM_DATA_REGIONS;
        
        /* Configure implicit code region */
        env->implicit_code_regions[idx].perm_exec = exec;
        env->implicit_code_regions[idx].enabled = enabled;
        qemu_log_mask(LOG_UNIMP, "HFI: Set permissions for implicit code region %d: "
                     "en:%d, x:%d\n",
                     idx, enabled, exec);
    } else {
        qemu_log_mask(LOG_GUEST_ERROR, "HFI: Invalid region number %d\n", region_number);
    }
}

void helper_hfi_print(CPURISCVState *env) {
    qemu_log_mask(LOG_UNIMP, "HFI: print, region_type=%llu, exit_handler=0x%016" PRIx64 "\n", 
        env->hfi_region_type,  env->hfi_exit_pc);
}