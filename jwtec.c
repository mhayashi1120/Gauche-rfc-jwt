/*
 * jwtec.c
 */

#include <openssl/ecdsa.h>

#include "jwtec.h"

/*
 * The following function is a dummy one; replace it for
 * your C function definitions.
 */

ScmObj test_jwtec(void)
{
    return SCM_MAKE_STR("jwtec is working");
}

ScmObj test_ecdsa(void)
{
    ECDSA_SIG *sig = ECDSA_SIG_new();

    ECDSA_SIG_free(sig);

    return SCM_MAKE_STR("HOGE");
}
    

/*
 * Module initialization function.
 */
extern void Scm_Init_jwteclib(ScmModule*);

void Scm_Init_jwtec(void)
{
    ScmModule *mod;

    /* Register this DSO to Gauche */
    SCM_INIT_EXTENSION(jwtec);

    /* Create the module if it doesn't exist yet. */
    mod = SCM_MODULE(SCM_FIND_MODULE("jwt.ecdsa", TRUE));

    /* Register stub-generated procedures */
    Scm_Init_jwteclib(mod);
}
