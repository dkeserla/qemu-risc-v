#include "hfi_helper.h"
#include "tcg/tcg.h"
#include "tcg/tcg-op.h"
#include "tcg/tcg-temp-internal.h"

#include "exec/helper-proto.h"
#include "qemu/log.h" // TODO remove

static bool trans_hfi_enter(DisasContext *ctx, arg_hfi_enter *arg)
{
    // Get the region_type from rs1 
    TCGv_i64 region_type = get_gpr(ctx, arg->rs1, EXT_NONE);

    // pulls the 64 bit value out of the register passed into rs2
    TCGv_i64 exit_handler_val = get_gpr(ctx, arg->rs2, EXT_NONE);
    
    gen_helper_hfi_enter(tcg_env, region_type, exit_handler_val);
    
    return true;
}

static bool trans_hfi_exit(DisasContext *ctx, arg_hfi_exit *arg)
{
    gen_helper_hfi_exit(tcg_env);
    return true;
}

static bool trans_hfi_set_region_size(DisasContext *ctx, arg_hfi_set_region_size *arg)
{
    TCGv_i64 region_number = get_gpr(ctx, arg->rd, EXT_NONE);

    TCGv_i64 base = get_gpr(ctx, arg->rs1, EXT_NONE);
    TCGv_i64 mask_or_bound = get_gpr(ctx, arg->rs2, EXT_NONE);
    
    gen_helper_hfi_set_region_size(tcg_env, region_number, base, mask_or_bound);
    
    return true;
}

static bool trans_hfi_set_region_permissions(DisasContext *ctx, arg_hfi_set_region_permissions *arg)
{
    TCGv_i64 region_number = get_gpr(ctx, arg->rs1, EXT_NONE);
    TCGv_i64 permission = get_gpr(ctx, arg->rs2, EXT_NONE);

    /* Extract the lower 8 bits from rs2 as permissions */
    TCGv_i64 perm = tcg_temp_new();
    tcg_gen_andi_i64(perm, permission, 0xFF);
    
    gen_helper_hfi_set_region_permissions(tcg_env, region_number, perm);
    
    tcg_temp_free_i64(perm);
    return true;
}

static bool trans_hlb0(DisasContext *ctx, arg_hlb0 *arg)
{
    qemu_log_mask(LOG_UNIMP, "translating hlb0\n");
    TCGv addr = get_address(ctx, arg->rs1, arg->imm);
    TCGv_i64 addr64 = tcg_temp_new_i64();
    TCGv_i64 region_num = tcg_constant_i64(0);
    
    tcg_gen_extu_tl_i64(addr64, addr);
    gen_helper_hfi_explicit_data_region_check_load(tcg_env, region_num, addr64);

    // TODO correct use of tcg_temp_free_i64? here and below
    tcg_temp_free_i64(addr64);
    // Byte access - no need to check end (same as beginning)
    return trans_lb(ctx, arg);
}

static bool trans_hlh0(DisasContext *ctx, arg_hlh0 *arg)
{
    qemu_log_mask(LOG_UNIMP, "translating hlh0\n");
    TCGv addr = get_address(ctx, arg->rs1, arg->imm);
    TCGv end_addr = tcg_temp_new();
    TCGv_i64 addr64 = tcg_temp_new_i64();
    TCGv_i64 end_addr64 = tcg_temp_new_i64();
    TCGv_i64 region_num = tcg_constant_i64(0);
    
    // Check start address
    tcg_gen_extu_tl_i64(addr64, addr);
    gen_helper_hfi_explicit_data_region_check_load(tcg_env, region_num, addr64);
    
    // Check end address (addr + 1) for halfword
    tcg_gen_addi_tl(end_addr, addr, 1);
    tcg_gen_extu_tl_i64(end_addr64, end_addr);
    gen_helper_hfi_explicit_data_region_check_load(tcg_env, region_num, end_addr64);
    
    tcg_temp_free_i64(end_addr);
    tcg_temp_free_i64(addr64);
    tcg_temp_free_i64(end_addr64);
    return trans_lh(ctx, arg);
}

static bool trans_hlw0(DisasContext *ctx, arg_hlw0 *arg)
{
    qemu_log_mask(LOG_UNIMP, "translating hlw0\n");
    TCGv addr = get_address(ctx, arg->rs1, arg->imm);
    TCGv end_addr = tcg_temp_new();
    TCGv_i64 addr64 = tcg_temp_new_i64();
    TCGv_i64 end_addr64 = tcg_temp_new_i64();
    TCGv_i64 region_num = tcg_constant_i64(0);
    
    // Check start address
    tcg_gen_extu_tl_i64(addr64, addr);
    gen_helper_hfi_explicit_data_region_check_load(tcg_env, region_num, addr64);
    
    // Check end address (addr + 3) for word
    tcg_gen_addi_tl(end_addr, addr, 3);
    tcg_gen_extu_tl_i64(end_addr64, end_addr);
    gen_helper_hfi_explicit_data_region_check_load(tcg_env, region_num, end_addr64);
    
    tcg_temp_free_i64(end_addr);
    tcg_temp_free_i64(addr64);
    tcg_temp_free_i64(end_addr64);
    return trans_lw(ctx, arg);
}

static bool trans_hlbu0(DisasContext *ctx, arg_hlbu0 *arg)
{
    qemu_log_mask(LOG_UNIMP, "translating hlbu0\n");
    TCGv addr = get_address(ctx, arg->rs1, arg->imm);
    TCGv_i64 addr64 = tcg_temp_new_i64();
    TCGv_i64 region_num = tcg_constant_i64(0);
    
    tcg_gen_extu_tl_i64(addr64, addr);
    gen_helper_hfi_explicit_data_region_check_load(tcg_env, region_num, addr64);
    
    tcg_temp_free_i64(addr64);
    // Byte access - no need to check end (same as beginning)
    return trans_lbu(ctx, arg);
}

static bool trans_hlhu0(DisasContext *ctx, arg_hlhu0 *arg)
{
    qemu_log_mask(LOG_UNIMP, "translating hlhu0\n");
    TCGv addr = get_address(ctx, arg->rs1, arg->imm);
    TCGv end_addr = tcg_temp_new();
    TCGv_i64 addr64 = tcg_temp_new_i64();
    TCGv_i64 end_addr64 = tcg_temp_new_i64();
    TCGv_i64 region_num = tcg_constant_i64(0);
    
    // Check start address
    tcg_gen_extu_tl_i64(addr64, addr);
    gen_helper_hfi_explicit_data_region_check_load(tcg_env, region_num, addr64);
    
    // Check end address (addr + 1) for halfword
    tcg_gen_addi_tl(end_addr, addr, 1);
    tcg_gen_extu_tl_i64(end_addr64, end_addr);
    gen_helper_hfi_explicit_data_region_check_load(tcg_env, region_num, end_addr64);
    
    tcg_temp_free_i64(end_addr);
    tcg_temp_free_i64(addr64);
    tcg_temp_free_i64(end_addr64);
    return trans_lhu(ctx, arg);
}

static bool trans_hlwu0(DisasContext *ctx, arg_hlwu0 *arg)
{
    qemu_log_mask(LOG_UNIMP, "translating hlwu0\n");
    TCGv addr = get_address(ctx, arg->rs1, arg->imm);
    TCGv end_addr = tcg_temp_new();
    TCGv_i64 addr64 = tcg_temp_new_i64();
    TCGv_i64 end_addr64 = tcg_temp_new_i64();
    TCGv_i64 region_num = tcg_constant_i64(0);
    
    // Check start address
    tcg_gen_extu_tl_i64(addr64, addr);
    gen_helper_hfi_explicit_data_region_check_load(tcg_env, region_num, addr64);
    
    // Check end address (addr + 3) for word
    tcg_gen_addi_tl(end_addr, addr, 3);
    tcg_gen_extu_tl_i64(end_addr64, end_addr);
    gen_helper_hfi_explicit_data_region_check_load(tcg_env, region_num, end_addr64);
    
    tcg_temp_free_i64(end_addr);
    tcg_temp_free_i64(addr64);
    tcg_temp_free_i64(end_addr64);
    return trans_lwu(ctx, arg);
}

static bool trans_hld0(DisasContext *ctx, arg_hld0 *arg)
{
    qemu_log_mask(LOG_UNIMP, "translating hld0\n");
    TCGv addr = get_address(ctx, arg->rs1, arg->imm);
    TCGv end_addr = tcg_temp_new();
    TCGv_i64 addr64 = tcg_temp_new_i64();
    TCGv_i64 end_addr64 = tcg_temp_new_i64();
    TCGv_i64 region_num = tcg_constant_i64(0);
    
    // Check start address
    tcg_gen_extu_tl_i64(addr64, addr);
    gen_helper_hfi_explicit_data_region_check_load(tcg_env, region_num, addr64);
    
    // Check end address (addr + 7) for doubleword
    tcg_gen_addi_tl(end_addr, addr, 7);
    tcg_gen_extu_tl_i64(end_addr64, end_addr);
    gen_helper_hfi_explicit_data_region_check_load(tcg_env, region_num, end_addr64);
    
    tcg_temp_free_i64(end_addr);
    tcg_temp_free_i64(addr64);
    tcg_temp_free_i64(end_addr64);
    return trans_ld(ctx, arg);
}

static bool trans_hsb0(DisasContext *ctx, arg_hsb0 *arg)
{
    qemu_log_mask(LOG_UNIMP, "translating hsb0\n");
    TCGv addr = get_address(ctx, arg->rs1, arg->imm);
    TCGv_i64 addr64 = tcg_temp_new_i64();
    TCGv_i64 region_num = tcg_constant_i64(0);
    
    tcg_gen_extu_tl_i64(addr64, addr);
    gen_helper_hfi_explicit_data_region_check_store(tcg_env, region_num, addr64);
    
    tcg_temp_free_i64(addr64);
    // Byte access - no need to check end (same as beginning)
    return trans_sb(ctx, arg);
}

static bool trans_hsh0(DisasContext *ctx, arg_hsh0 *arg)
{
    qemu_log_mask(LOG_UNIMP, "translating hsh0\n");
    TCGv addr = get_address(ctx, arg->rs1, arg->imm);
    TCGv end_addr = tcg_temp_new();
    TCGv_i64 addr64 = tcg_temp_new_i64();
    TCGv_i64 end_addr64 = tcg_temp_new_i64();
    TCGv_i64 region_num = tcg_constant_i64(0);
    
    // Check start address
    tcg_gen_extu_tl_i64(addr64, addr);
    gen_helper_hfi_explicit_data_region_check_store(tcg_env, region_num, addr64);
    
    // Check end address (addr + 1) for halfword
    tcg_gen_addi_tl(end_addr, addr, 1);
    tcg_gen_extu_tl_i64(end_addr64, end_addr);
    gen_helper_hfi_explicit_data_region_check_store(tcg_env, region_num, end_addr64);
    
    tcg_temp_free_i64(end_addr);
    tcg_temp_free_i64(addr64);
    tcg_temp_free_i64(end_addr64);
    return trans_sh(ctx, arg);
}

static bool trans_hsw0(DisasContext *ctx, arg_hsw0 *arg)
{
    qemu_log_mask(LOG_UNIMP, "translating hsw0\n");
    TCGv addr = get_address(ctx, arg->rs1, arg->imm);
    TCGv end_addr = tcg_temp_new();
    TCGv_i64 addr64 = tcg_temp_new_i64();
    TCGv_i64 end_addr64 = tcg_temp_new_i64();
    TCGv_i64 region_num = tcg_constant_i64(0);
    
    // Check start address
    tcg_gen_extu_tl_i64(addr64, addr);
    gen_helper_hfi_explicit_data_region_check_store(tcg_env, region_num, addr64);
    
    // Check end address (addr + 3) for word
    tcg_gen_addi_tl(end_addr, addr, 3);
    tcg_gen_extu_tl_i64(end_addr64, end_addr);
    gen_helper_hfi_explicit_data_region_check_store(tcg_env, region_num, end_addr64);
    
    tcg_temp_free_i64(end_addr);
    tcg_temp_free_i64(addr64);
    tcg_temp_free_i64(end_addr64);
    return trans_sw(ctx, arg);
}

static bool trans_hsd0(DisasContext *ctx, arg_hsd0 *arg)
{
    qemu_log_mask(LOG_UNIMP, "translating hsd0\n");
    TCGv addr = get_address(ctx, arg->rs1, arg->imm);
    TCGv end_addr = tcg_temp_new();
    TCGv_i64 addr64 = tcg_temp_new_i64();
    TCGv_i64 end_addr64 = tcg_temp_new_i64();
    TCGv_i64 region_num = tcg_constant_i64(0);
    
    // Check start address
    tcg_gen_extu_tl_i64(addr64, addr);
    gen_helper_hfi_explicit_data_region_check_store(tcg_env, region_num, addr64);
    
    // Check end address (addr + 7) for doubleword
    tcg_gen_addi_tl(end_addr, addr, 7);
    tcg_gen_extu_tl_i64(end_addr64, end_addr);
    gen_helper_hfi_explicit_data_region_check_store(tcg_env, region_num, end_addr64);
    
    tcg_temp_free_i64(end_addr);
    tcg_temp_free_i64(addr64);
    tcg_temp_free_i64(end_addr64);
    return trans_sd(ctx, arg);
}