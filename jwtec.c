/*
 * jwtec.c
 */

/* Ref: */
/* https://www.jnsa.org/seminar/pki-day/2011/data/02_kanaoka.pdf */
/* https://github.com/OpenSC/OpenSC/pull/2438 */

/* About EC Public Key:  */
/* https://tex2e.github.io/rfc-translater/html/rfc5480.html */
/* https://www.secg.org/sec1-v2.pdf */

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#include "jwtec.h"

typedef struct binary_st
{
    unsigned char * data;
    size_t size;
} Binary;

static void purgeBinary(Binary * b)
{
    if (b == NULL) {
        return;
    }

    if (b->data != NULL) {
        b->data = NULL;
        b->size = 0;
    }
}

static size_t signatureSize(size_t digestLength)
{
    /* TODO FIXME not enough understand EC algorithm yet, but maybe enough size */
    return digestLength * 4;
}

static BIGNUM * ScmUVectorToBignum(const ScmUVector * v, BN_CTX * ctx)
{
    BIGNUM * bn = ctx != NULL ? BN_CTX_get(ctx) : BN_new();

    if (bn == NULL) {
        return NULL;
    }

    const unsigned char *body = (unsigned char*)SCM_UVECTOR_ELEMENTS(v);
    const int len = SCM_UVECTOR_SIZE(v);

    BN_bin2bn(body, len, bn);

    return bn;
}

static ScmObj bignumToVector(BIGNUM * bn)
{
    int numBytes = BN_num_bytes(bn);
    unsigned char * array =  (unsigned char *)SCM_NEW_ATOMIC_ARRAY(char, numBytes);
    int size = BN_bn2bin(bn, array);

    /* Check misunderstanding or not. */
    SCM_ASSERT(numBytes == size);

    return Scm_MakeUVector(SCM_CLASS_U8VECTOR, size, array);
}

static ScmObj signatureToPairs(const ECDSA_SIG * signature)
{
    BIGNUM * r = NULL, * s = NULL;
    ScmObj result = NULL;

    ECDSA_SIG_get0(signature, (const BIGNUM**)&r, (const BIGNUM**)&s);

    ScmObj scm_r = bignumToVector(r);
    ScmObj scm_s = bignumToVector(s);

    result = Scm_Cons(scm_r, scm_s);

 exit:

    return result;
}

static EVP_PKEY * makeKey()
{
    EVP_PKEY * key = EVP_PKEY_new();

    if (key == NULL) {
        return NULL;
    }

    EVP_PKEY_set_type(key, EVP_PKEY_EC);

    return key;
}

static EVP_PKEY_CTX * loadPrivateKey(BIGNUM * priv, const char * curve)
{
    EVP_PKEY * key = NULL;
    EVP_PKEY_CTX * ctx = NULL;
    OSSL_PARAM_BLD * builder = NULL;
    OSSL_PARAM * params = NULL;

    key = makeKey();
    builder = OSSL_PARAM_BLD_new();

    if (key == NULL || builder == NULL){
        goto fail;
    }

    if (! (OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_PRIV_KEY, priv) &&
           OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_PKEY_PARAM_GROUP_NAME, curve, 0))) {
        goto fail;
    }

    params = OSSL_PARAM_BLD_to_param(builder);
    ctx = EVP_PKEY_CTX_new(key, NULL);

    if (! (EVP_PKEY_fromdata_init(ctx) &&
           EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_KEYPAIR, params))) {
        goto fail;
    }

    goto exit;

 fail:
    if (ctx != NULL) EVP_PKEY_CTX_free(ctx);

 exit:
    if (builder != NULL) OSSL_PARAM_BLD_free(builder);
    if (params != NULL) OSSL_PARAM_free(params);

    return ctx;
}

/* ref: https://www.secg.org/sec1-v2.pdf */
/* 2.3.3 Elliptic-Curve-Point-to-Octet-String Conversion */
static Binary * publicKeyOctetString(const char * curve, const BIGNUM * X, const BIGNUM * Y, BN_CTX * ctx)
{
    const int nid = EC_curve_nist2nid(curve);
    Binary * store = NULL;
    EC_GROUP * group = NULL;
    EC_POINT * point = NULL;
    unsigned char * octetKey = NULL;

    if (EVP_PKEY_NONE == nid) {
        return NULL;
    }

    group = EC_GROUP_new_by_curve_name(nid);

    if (group == NULL) {
        goto fail;
    }

    point = EC_POINT_new(group);

    if (point == NULL) {
        goto fail;
    }

    if (! EC_POINT_set_affine_coordinates(group, point, X, Y, ctx)) {
        goto fail;
    }

    /* TODO Maybe enough size here */
    int len = BN_num_bytes(X) + BN_num_bytes(Y) + 1;

    octetKey = SCM_MALLOC(len);

    size_t size;

    if ((size = EC_POINT_point2oct(group, point,
                                   POINT_CONVERSION_UNCOMPRESSED,
                                   octetKey, len, ctx)) <= 0) {
        goto fail;
    }

    store = SCM_MALLOC(sizeof(Binary));

    store->data = octetKey;
    store->size = size;

    goto exit;

 fail:
    store = NULL;

 exit:
    if (group != NULL) EC_GROUP_free(group);
    if (point != NULL) EC_POINT_free(point);

    return store;
}

static EVP_PKEY_CTX * loadPublicKey(BIGNUM * X, BIGNUM * Y, const char * curve, BN_CTX * bnctx)
{
    OSSL_PARAM_BLD * builder = NULL;
    OSSL_PARAM * params = NULL;
    EVP_PKEY_CTX * ctx = NULL;
    EVP_PKEY * key = NULL;
    Binary * octetKey = NULL;

    key = makeKey();
    builder = OSSL_PARAM_BLD_new();

    if (key == NULL || builder == NULL) {
        goto fail;
    }

    octetKey = publicKeyOctetString(curve, X, Y, bnctx);

    if (octetKey == NULL) {
        goto fail;
    }

    if (! (OSSL_PARAM_BLD_push_octet_string(builder, OSSL_PKEY_PARAM_PUB_KEY, octetKey->data, octetKey->size) &&
           OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_PKEY_PARAM_GROUP_NAME, curve, 0))) {
        goto fail;
    }

    params = OSSL_PARAM_BLD_to_param(builder);
    ctx = EVP_PKEY_CTX_new(key, NULL);

    if (! (EVP_PKEY_fromdata_init(ctx) &&
           EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params))) {
        goto fail;
    }

    goto exit;

 fail:
    if (ctx != NULL) EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

 exit:
    if (octetKey != NULL) purgeBinary(octetKey);
    if (builder != NULL) OSSL_PARAM_BLD_free(builder);
    if (params != NULL) OSSL_PARAM_free(params);

    return ctx;
}

/* -> VERIFIED?:<boolean> */
ScmObj doVerify(ScmString *curveType, const ScmUVector *DGST,
                const ScmUVector *R, const ScmUVector *S,
                const ScmUVector *X, const ScmUVector *Y)
{
    char * errorMsg = NULL;
    ScmObj result = NULL;
    BIGNUM * pubX = NULL, * pubY = NULL, * r = NULL, * s = NULL;
    EVP_MD_CTX * mdctx = NULL;
    ECDSA_SIG * signature = NULL;
    BN_CTX * bnctx = BN_CTX_new();

    const char * curve = Scm_GetStringConst(curveType);
    EVP_PKEY_CTX * pubCtx = NULL;

    BN_CTX_start(bnctx);

    pubX = ScmUVectorToBignum(X, bnctx);
    pubY = ScmUVectorToBignum(Y, bnctx);

    if (pubX == NULL || pubY == NULL) {
        errorMsg = "Failed construct bignum X/Y";
        goto exit;
    }

    if ((pubCtx = loadPublicKey(pubX, pubY, curve, bnctx)) == NULL) {
        errorMsg = "Failed construct public key";
        goto exit;
    }

    signature = ECDSA_SIG_new();

    /* Not BN_CTX here since pass to ECDSA_SIG_set0 `set0` method */
    /* See man `crypto(7ssl)` `LIBRARY CONVENTIONS` section */
    r = ScmUVectorToBignum(R, NULL);
    s = ScmUVectorToBignum(S, NULL);

    if (signature == NULL || r == NULL || s == NULL) {
        errorMsg = "Failed construct signature.";
        goto exit;
    }

    if (!ECDSA_SIG_set0(signature, r, s)) {
        errorMsg = "Failed while set signature.";
        goto exit;
    }

    const unsigned char * dgst = (unsigned char*)SCM_UVECTOR_ELEMENTS(DGST);
    const int dgstlen = SCM_UVECTOR_SIZE(DGST);

    if ((mdctx = EVP_MD_CTX_new()) == NULL) {
        errorMsg = "Failed start digest context.";
        goto exit;
    }

    const unsigned char * sigtop = SCM_MALLOC(signatureSize(dgstlen));
    unsigned char * sig = (unsigned char *)sigtop;
    int siglen = i2d_ECDSA_SIG(signature, &sig);

    if (siglen < 0) {
        errorMsg = "Failed convert ECDSA signature";
        goto exit;
    }

    EVP_MD_CTX_set_pkey_ctx(mdctx, pubCtx);
    EVP_PKEY * pkey = EVP_PKEY_CTX_get0_pkey(pubCtx);

    if (! EVP_DigestVerifyInit(mdctx, &pubCtx, NULL, NULL, pkey)) {
        errorMsg = "Failed digest verify init";
        goto exit;
    }

    /* `sig` point to next of the buffer */
    SCM_ASSERT(sigtop + siglen == sig);

    if (EVP_DigestVerify(mdctx, sigtop, siglen, dgst, dgstlen) == 1) {
        result = SCM_TRUE;
    } else {
        result = SCM_FALSE;
    }

 exit:
    if (mdctx != NULL) EVP_MD_CTX_free(mdctx);
    if (signature != NULL) ECDSA_SIG_free(signature);

    if (bnctx != NULL) {
        BN_CTX_end(bnctx);
        BN_CTX_free(bnctx);
    }

    if (errorMsg != NULL) {
        Scm_Error(errorMsg);
    }

    SCM_ASSERT(result != NULL);

    return result;
}

/* curveType: NIST / SN */
/* -> (R:<u8vector> . S:<u8vector>) */
ScmObj doSign(ScmString *curveType, const ScmUVector *DGST, const ScmUVector *PRV)
{
    char * errorMsg = NULL;
    ScmObj result = NULL;
    BIGNUM * prv = NULL;
    ECDSA_SIG * signature = NULL;
    EVP_MD_CTX * mdctx = NULL;
    unsigned char * sig = NULL;
    BN_CTX * bnctx = BN_CTX_new();

    const char * curve = Scm_GetStringConst(curveType);
    EVP_PKEY_CTX * privCtx = NULL;

    BN_CTX_start(bnctx);

    if ((prv = ScmUVectorToBignum(PRV, bnctx)) == NULL) {
        errorMsg = "Failed construct bignum PRV";
        goto exit;
    }

    if ((privCtx = loadPrivateKey(prv, curve)) == NULL) {
        errorMsg = "Key construction failed.";
        goto exit;
    }

    const unsigned char * dgst = (unsigned char *)SCM_UVECTOR_ELEMENTS(DGST);
    const int dgstlen = SCM_UVECTOR_SIZE(DGST);

    if ((mdctx = EVP_MD_CTX_new()) == NULL) {
        errorMsg = "Failed start digest context.";
        goto exit;
    }

    sig = SCM_MALLOC(signatureSize(dgstlen));
    size_t siglen;

    EVP_MD_CTX_set_pkey_ctx(mdctx, privCtx);
    EVP_PKEY * pkey = EVP_PKEY_CTX_get0_pkey(privCtx);

    if (! EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey)) {
        errorMsg = "Failed digest sign init";
        goto exit;
    }

    if (! EVP_DigestSign(mdctx, sig, &siglen, dgst, dgstlen)) {
        errorMsg = "Failed to sign by private key";
        goto exit;
    }

    if ((signature = ECDSA_SIG_new()) == NULL) {
        errorMsg = "Failed construct ECDSA signature";
        goto exit;
    }

    if (d2i_ECDSA_SIG(&signature, (const unsigned char**)&sig, siglen) == NULL) {
        errorMsg = "Failed convert signature";
        goto exit;
    }

    result = signatureToPairs(signature);

    if (result == NULL) {
        errorMsg = "Failed construct signature";
        goto exit;
    }

 exit:
    if (mdctx != NULL) EVP_MD_CTX_free(mdctx);
    if (signature != NULL) ECDSA_SIG_free(signature);

    if (bnctx != NULL) {
        BN_CTX_end(bnctx);
        BN_CTX_free(bnctx);
    }

    if (errorMsg != NULL) {
        Scm_Error(errorMsg);
    }

    SCM_ASSERT(result != NULL);

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
    SCM_INIT_EXTENSION(rfc__jwtec);

    /* Create the module if it doesn't exist yet. */
    mod = SCM_MODULE(SCM_FIND_MODULE("rfc.jwt.ecdsa", TRUE));

    /* Register stub-generated procedures */
    Scm_Init_jwteclib(mod);
}
