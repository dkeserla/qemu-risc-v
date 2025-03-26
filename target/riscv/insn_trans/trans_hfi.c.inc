#include "hfi_helper.h"



// TODO: Modify the arg to be one that will contain the exhit handler
static bool trans_hfi_enter(DisasContext *ctx, arg_hfi_enter *arg)
{
    uint64_t exit_handler = 0xabcdabcdabcdabcdULL;  // constant for now (derive from arg)
    gen_helper_hfi_enter(tcg_env, tcg_const_ptr(ctx->cs), tcg_const_i64(exit_handler));
    return true;
}

static bool trans_hfi_exit(DisasContext *ctx, arg_hfi_exit *arg)
{
    gen_helper_hfi_exit(tcg_env, tcg_const_ptr(ctx->cs));
    return true;
}
