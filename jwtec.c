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


/* id: 415 name: P-256 */
/* id: 715 name: P-384 */
/* id: 716 name: P-521 */

    /* | ES256             | ECDSA using P-256 and SHA-256 | */
    /* | ES384             | ECDSA using P-384 and SHA-384 | */
    /* | ES512             | ECDSA using P-521 and SHA-512 | */

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


    EC_builtin_curve curves[1024];
    EC_builtin_curve * curve = curves;
    /* size_t i = EC_get_builtin_curves(&curve, 0); */
    /* if (i > 0) { */
    /* 	printf("%d %s: %s\n", curve.nid, EC_curve_nid2nist(curve.nid), curve.comment); */
    /* } */
    
    int i = 0;
    size_t size;
    while (i < 30 && ((size = EC_get_builtin_curves(curve, 1024)) != 0))
    {
    	printf("%d %s: %s size: %d\n", curve->nid, EC_curve_nid2nist(curve->nid), curve->comment, size);
    	i++;
    }

    i = 0;
    while (i < 1000) {
	const char * name = EC_curve_nid2nist(i);

	if (name != NULL) {
	    printf("id: %d name: %s\n", i, name);
	}

	i++;
    }

    printf("id: %d\n", EC_curve_nist2nid("P-256"));
    printf("id: %d\n", EC_curve_nist2nid("P-384"));
    printf("id: %d\n", EC_curve_nist2nid("P-521"));
    

    return SCM_MAKE_STR("HOGEあいうえお");
}
    

ScmObj signWithKey(BIGNUM *prv, const unsigned char *dgst, int dgstlen)
{
    /* TODO curve */
    int nid = EC_curve_nist2nid("P-256");
    EC_KEY * privKey = EC_KEY_new_by_curve_name(nid);

    if (! EC_KEY_set_private_key(privKey, prv)) {
	Scm_Error("Failed to set private key");
    }

    int sigSize = ECDSA_size(privKey);

    /* TODO malloc? */
    unsigned char sig[1024];
    unsigned int siglen;

    if (! ECDSA_sign(0, dgst, dgstlen, sig, &siglen, privKey)) {
	Scm_Error("Failed to sign by private key");
    }

    return Scm_MakeString(sig, siglen, siglen, SCM_STRING_COPYING);
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
