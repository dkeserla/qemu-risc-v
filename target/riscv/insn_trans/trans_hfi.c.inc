#include "hfi_helper.h"
#include "tcg/tcg.h"
#include "tcg/tcg-op.h"

#include "exec/helper-proto.h"

static bool trans_hfi_enter(DisasContext *ctx, arg_hfi_enter *arg)
{
    // pulls the 64 bit value out of the register passed into rs1
    TCGv_i64 exit_handler_val = get_gpr(ctx, arg->rs1, EXT_NONE);
    gen_helper_hfi_enter(tcg_env, exit_handler_val);
    return true;
}

static bool trans_hfi_exit(DisasContext *ctx, arg_hfi_exit *arg)
{
    gen_helper_hfi_exit(tcg_env);
    return true;
}

static bool trans_hfi_set_region_size(DisasContext *ctx, arg_hfi_set_region_size *arg)
{
    TCGv_i32 region_number = tcg_const_i32(arg->region_number);
    TCGv_i64 base = get_gpr(ctx, arg->rs1, EXT_NONE);
    TCGv_i64 mask_or_bound = get_gpr(ctx, arg->rs2, EXT_NONE);
    
    gen_helper_hfi_set_region_size(tcg_env, region_number, base, mask_or_bound);
    
    tcg_temp_free_i32(region_number);
    return true;
}

static bool trans_hfi_set_region_permissions(DisasContext *ctx, arg_hfi_set_region_permissions *arg)
{
    TCGv_i32 region_number = tcg_const_i32(arg->region_number);
    TCGv_i64 permission_64 = get_gpr(ctx, arg->rs1, EXT_NONE);
    TCGv_i32 permission = tcg_temp_new_i32();
    
    /* Extract the lower 8 bits from rs1 as permissions */
    tcg_gen_extrl_i64_i32(permission, permission_64);
    tcg_gen_andi_i32(permission, permission, 0xFF);
    
    gen_helper_hfi_set_region_permissions(tcg_env, region_number, permission);
    
    tcg_temp_free_i32(region_number);
    tcg_temp_free_i32(permission);
    return true;
}
