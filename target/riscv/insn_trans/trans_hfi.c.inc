#include "hfi_helper.h"
#include "tcg/tcg.h"
#include "tcg/tcg-op.h"
#include "tcg/tcg-temp-internal.h"

#include "exec/helper-proto.h"

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
