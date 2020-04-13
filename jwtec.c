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
    
BIGNUM * ScmUVectorToBignum(const ScmUVector * v)
{
    /* TODO */
    BIGNUM * bn = BN_new();
    const unsigned char *body = (unsigned char*)SCM_UVECTOR_ELEMENTS(v);
    const int len = SCM_UVECTOR_SIZE(v);

    BN_bin2bn(body, len, bn);

    return bn;
}

ScmObj verifyByKey(const char *curveType, const ScmUVector *DGST,
		   const ScmUVector *R, const ScmUVector *S,
		   const ScmUVector *X, const ScmUVector *Y)
{
    BIGNUM *x = ScmUVectorToBignum(X);
    BIGNUM *y = ScmUVectorToBignum(Y);
    const int nid = EC_curve_nist2nid(curveType);
    EC_KEY * pubKey = EC_KEY_new_by_curve_name(nid);
    char * errorMsg = NULL;

    /* x, y seems non changed const values */
    if (! EC_KEY_set_public_key_affine_coordinates(pubKey, (BIGNUM*)x, (BIGNUM*)y)) {
	errorMsg = "Failed to set public key";
	goto exit;
    }

    ECDSA_SIG * signature = ECDSA_SIG_new();
    BIGNUM *r = ScmUVectorToBignum(R);
    BIGNUM *s = ScmUVectorToBignum(S);

    /* TODO check result */
    ECDSA_SIG_set0(signature, r, s);

    const int sigSize = ECDSA_size(pubKey);
    const char *dgst = (char*)SCM_UVECTOR_ELEMENTS(DGST);
    const int dgstlen = SCM_UVECTOR_SIZE(DGST);
    const int verifyResult = ECDSA_do_verify(dgst, dgstlen, signature, pubKey);
    
    ScmObj result = NULL;

    if (! verifyResult) {
	result = SCM_FALSE;
	goto exit;
    }
    
    result = SCM_TRUE;

exit:
    /* TODO when not initialized, what value is ? */
    if (pubKey != NULL) EC_KEY_free(pubKey);
    if (x != NULL) BN_free(x);
    if (y != NULL) BN_free(y);
    if (r != NULL) BN_free(r);
    if (s != NULL) BN_free(s);
    if (signature != NULL) ECDSA_SIG_free(signature);

    if (errorMsg != NULL) {
	Scm_Error(errorMsg);
    }

    return result;
}

ScmObj signWithKey(const char * curveType, const ScmUVector *DGST, const ScmUVector *PRV)
{
    char * errorMsg = NULL;

    BIGNUM *prv = ScmUVectorToBignum(PRV);
    /* TODO curve */
    /* "P-256" "P-384" "P-521" */
    const int nid = EC_curve_nist2nid(curveType);

    /* TODO reconsider */
    if (nid <= 0) {
	errorMsg = "CurveType not found.";
	goto exit;
    }

    EC_KEY * privKey = EC_KEY_new_by_curve_name(nid);

    if (! EC_KEY_set_private_key(privKey, prv)) {
	errorMsg = "Failed to set private key";
	goto exit;
    }

    const int sigSize = ECDSA_size(privKey);

    /* TODO malloc? */
    unsigned char sig[1024];
    unsigned int siglen;
    const char * dgst = (char *)SCM_UVECTOR_ELEMENTS(DGST);
    const int dgstlen = SCM_UVECTOR_SIZE(DGST);

    const int signResult = ECDSA_sign(0, dgst, dgstlen, sig, &siglen, privKey);

    if (! signResult) {
	errorMsg = "Failed to sign by private key";
	goto exit;
    }

    const ScmObj result = Scm_MakeString(sig, siglen, siglen, SCM_STRING_COPYING);

exit:
    if (privKey != NULL) EC_KEY_free(privKey);
    if (prv != NULL) BN_free(prv);

    if (errorMsg != NULL ) {
	Scm_Error(errorMsg);
    }

    return result;
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
