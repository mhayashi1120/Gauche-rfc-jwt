/*
 * jwtec.c
 */

#include <openssl/ecdsa.h>
#include <openssl/bn.h>

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

    EC_KEY *key = EC_KEY_new();

/* int EC_KEY_set_public_key_affine_coordinates(EC_KEY *key, BIGNUM *x, */
/*                                              BIGNUM *y); */
/* int EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *prv); */
/* int EC_KEY_check_key(const EC_KEY *key); */
/* int EC_KEY_can_sign(const EC_KEY *eckey); */
/* const EC_METHOD *EC_GF2m_simple_method(void); */
/* const EC_METHOD *EC_GROUP_method_of(const EC_GROUP *group); */
/* const EC_METHOD *EC_POINT_method_of(const EC_POINT *point); */
/* EC_GROUP *EC_GROUP_new(const EC_METHOD *meth); */
/* EC_POINT *EC_POINT_new(const EC_GROUP *group); */
/* EC_KEY *EC_KEY_new_method(ENGINE *engine); */
/* ENGINE *EC_KEY_get0_engine(const EC_KEY *eckey); */
/* ECDSA_SIG *ECDSA_do_sign(const unsigned char *dgst, int dgst_len, */
/*                          EC_KEY *eckey); */
/* int ECDSA_do_verify(const unsigned char *dgst, int dgst_len, */
/*                     const ECDSA_SIG *sig, EC_KEY *eckey); */
/* int ECDSA_sign_setup(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv, BIGNUM **rp); */
/* int ECDSA_sign(int type, const unsigned char *dgst, int dgstlen, */
/*                unsigned char *sig, unsigned int *siglen, EC_KEY *eckey); */
/* int ECDSA_verify(int type, const unsigned char *dgst, int dgstlen, */
/*                  const unsigned char *sig, int siglen, EC_KEY *eckey); */


/* BIGNUM *BN_new(void); */
/* void BN_clear_free(BIGNUM *a); */
/* BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret); */
/* int BN_bn2bin(const BIGNUM *a, unsigned char *to); */

    BIGNUM* bn1 = BN_new();
    unsigned char *s = "\377";
    unsigned char s2[256];

    BN_bin2bn(s, 2, bn1);

    int len = BN_bn2bin(bn1, s2);
    /* fprintf(stdout, "len: %d", len); */
    /* BN_print_fp(stdout, bn1); */

    BN_clear_free(bn1);

    EC_KEY_free(key);

    ECDSA_SIG_free(sig);

    return SCM_MAKE_STR("HOGEあいうえお");
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
