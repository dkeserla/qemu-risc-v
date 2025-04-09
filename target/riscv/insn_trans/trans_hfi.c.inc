#include "hfi_helper.h"
#include "tcg/tcg.h"
#include "tcg/tcg-op.h"

#include "exec/helper-proto.h"

typedef arg_r1 arg_hfi_enter;


// TODO: Modify the arg to be one that will contain the exhit handler
static bool trans_hfi_enter(DisasContext *ctx, arg_hfi_enter *arg)
{
    assert(false && "Hit trans_hfi_enter");
    // uint64_t exit_handler = 0xabcdabcdabcdabcdULL;  // constant for now (derive from arg)
    // gen_helper_hfi_enter(tcg_env, tcg_constant_tl(exit_handler));
    // fprintf(stderr, "!!! HFI ENTER TRANSLATE RUNNING !!!\n");
    // gen_helper_hfi_enter(tcg_env, cpu_gpr[arg->rs1]);
    return true;
}

static bool trans_hfi_exit(DisasContext *ctx, arg_hfi_exit *arg)
{
    // gen_helper_hfi_exit(tcg_env);
    return true;
}
