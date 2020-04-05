/*
 * jwt.c
 */

#include "jwt.h"

/*
 * The following function is a dummy one; replace it for
 * your C function definitions.
 */

ScmObj test_jwt(void)
{
    return SCM_MAKE_STR("jwt is working");
}

/*
 * Module initialization function.
 */
extern void Scm_Init_jwtlib(ScmModule*);

void Scm_Init_jwt(void)
{
    ScmModule *mod;

    /* Register this DSO to Gauche */
    SCM_INIT_EXTENSION(jwt);

    /* Create the module if it doesn't exist yet. */
    mod = SCM_MODULE(SCM_FIND_MODULE("jwt", TRUE));

    /* Register stub-generated procedures */
    Scm_Init_jwtlib(mod);
}
