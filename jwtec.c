/*
 * jwtec.c
 */

/* Ref: */
/* https://www.jnsa.org/seminar/pki-day/2011/data/02_kanaoka.pdf */

#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/objects.h>

#include "jwtec.h"

static BIGNUM * ScmUVectorToBignum(const ScmUVector * v)
{
    BIGNUM * bn = BN_new();
    const unsigned char *body = (unsigned char*)SCM_UVECTOR_ELEMENTS(v);
    const int len = SCM_UVECTOR_SIZE(v);

    BN_bin2bn(body, len, bn);

    return bn;
}

static ScmObj readBNToVector(BIGNUM * bn)
{
    int numBytes = BN_num_bytes(bn);
    char * array =  SCM_NEW_ATOMIC_ARRAY(char, numBytes);
    int size = BN_bn2bin(bn, array);

    /* Some of misunderstanding or not. */
    SCM_ASSERT(numBytes == size);

    return Scm_MakeUVector(SCM_CLASS_U8VECTOR, size, array);
}

static ScmObj ECSignatureToVectors(const ECDSA_SIG * signature)
{
    BIGNUM * r = NULL, * s = NULL;

    ECDSA_SIG_get0(signature, (const BIGNUM**)&r, (const BIGNUM**)&s);

    ScmObj scm_r = readBNToVector(r);
    ScmObj scm_s = readBNToVector(s);

    ScmObj result = Scm_Cons(scm_r, scm_s);

 exit:

    return result;
}

static EC_KEY * ensureECKeyByCurveType(ScmString * curveType)
{
    const char * curve_type = Scm_GetStringConst(curveType);
    int nid = EC_curve_nist2nid(curve_type);

    if (nid == NID_undef) {
        nid = OBJ_sn2nid(curve_type);
    }

    if (nid <= 0) {
        return NULL;
    }

    return EC_KEY_new_by_curve_name(nid);
}


ScmObj doVerify(ScmString * curveType, const ScmUVector *DGST,
                const ScmUVector *R, const ScmUVector *S,
                const ScmUVector *X, const ScmUVector *Y)
{
    BIGNUM * x = NULL, * y = NULL, * r = NULL, * s = NULL;
    EC_KEY * pubKey = NULL;
    char * errorMsg = NULL;
    ECDSA_SIG * signature = NULL;
    ScmObj result = NULL;

    x = ScmUVectorToBignum(X);
    y = ScmUVectorToBignum(Y);

    pubKey = ensureECKeyByCurveType(curveType);

    if (pubKey == NULL) {
        errorMsg = "Key construction failed.";
        goto exit;
    }

    /* x, y seems non changed const values */
    if (! EC_KEY_set_public_key_affine_coordinates(pubKey, x, y)) {
        errorMsg = "Failed to set public key.";
        goto exit;
    }

    signature = ECDSA_SIG_new();

    r = ScmUVectorToBignum(R);
    s = ScmUVectorToBignum(S);

    if (!ECDSA_SIG_set0(signature, r, s)) {
        errorMsg = "Failed to set signature.";
        goto exit;
    }

    r = NULL, s = NULL;

    const char * dgst = (char*)SCM_UVECTOR_ELEMENTS(DGST);
    const int dgstlen = SCM_UVECTOR_SIZE(DGST);
    const int verifyResult = ECDSA_do_verify(dgst, dgstlen, signature, pubKey);

    if (! verifyResult) {
        result = SCM_FALSE;
        goto exit;
    }

    result = SCM_TRUE;

 exit:
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

/* curveType: NIST / SN */
/* Return: R and S signed values as <u8vector>. */
ScmObj doSign(ScmString * curveType, const ScmUVector * DGST, const ScmUVector * PRV)
{
    char * errorMsg = NULL;
    EC_KEY * privKey = NULL;
    BIGNUM * prv = NULL;
    ECDSA_SIG * signature = NULL;

    privKey = ensureECKeyByCurveType(curveType);

    if (privKey == NULL) {
        errorMsg = "Key construction failed.";
        goto exit;
    }

    /* EC_KEY_set_asn1_flag(privKey, OPENSSL_EC_NAMED_CURVE); */
    /* EC_KEY_set_conv_form(privKey, POINT_CONVERSION_UNCOMPRESSED); */

    prv = ScmUVectorToBignum(PRV);

    if (! EC_KEY_set_private_key(privKey, prv)) {
        errorMsg = "Failed to set private key";
        goto exit;
    }

    const char * dgst = (char *)SCM_UVECTOR_ELEMENTS(DGST);
    const int dgstlen = SCM_UVECTOR_SIZE(DGST);

    signature = ECDSA_do_sign(dgst, dgstlen, privKey);

    if (signature == NULL) {
        errorMsg = "Failed to sign by private key";
        goto exit;
    }

    ScmObj result = ECSignatureToVectors(signature);

 exit:
    if (privKey != NULL) EC_KEY_free(privKey);
    if (prv != NULL) BN_free(prv);
    if (signature != NULL) ECDSA_SIG_free(signature);

    if (errorMsg != NULL ) {
        Scm_Error(errorMsg);
    }

    return result;
}

/*
 * Module initialization function.
 */
extern void Scm_Init_jwteclib(ScmModule*);

void Scm_Init_rfc__jwtec(void)
{
    ScmModule *mod;

    /* Register this DSO to Gauche */
    SCM_INIT_EXTENSION(jwtec);

    /* Create the module if it doesn't exist yet. */
    mod = SCM_MODULE(SCM_FIND_MODULE("rfc.jwt.ecdsa", TRUE));

    /* Register stub-generated procedures */
    Scm_Init_jwteclib(mod);
}
