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
