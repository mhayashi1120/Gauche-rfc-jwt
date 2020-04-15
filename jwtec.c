/*
 * jwtec.c
 */

#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/objects.h>

#include "jwtec.h"

/* OpenSSL::PKey::EC.builtin_curves */
/* [["secp112r1", "SECG/WTLS curve over a 112 bit prime field"], */
/* ["secp112r2", "SECG curve over a 112 bit prime field"], */
/* ["secp128r1", "SECG curve over a 128 bit prime field"], */
/* ["secp128r2", "SECG curve over a 128 bit prime field"], */
/* ["secp160k1", "SECG curve over a 160 bit prime field"], */
/* ["secp160r1", "SECG curve over a 160 bit prime field"], */
/* ["secp160r2", "SECG/WTLS curve over a 160 bit prime field"], */
/* ["secp192k1", "SECG curve over a 192 bit prime field"], */
/* ["secp224k1", "SECG curve over a 224 bit prime field"], */
/* ["secp224r1", "NIST/SECG curve over a 224 bit prime field"], */
/* ["secp256k1", "SECG curve over a 256 bit prime field"], */
/* ["secp384r1", "NIST/SECG curve over a 384 bit prime field"], */
/* ["secp521r1", "NIST/SECG curve over a 521 bit prime field"], */
/* ["prime192v1", "NIST/X9.62/SECG curve over a 192 bit prime field"], */
/* ["prime192v2", "X9.62 curve over a 192 bit prime field"], */
/* ["prime192v3", "X9.62 curve over a 192 bit prime field"], */
/* ["prime239v1", "X9.62 curve over a 239 bit prime field"], */
/* ["prime239v2", "X9.62 curve over a 239 bit prime field"], */
/* ["prime239v3", "X9.62 curve over a 239 bit prime field"], */
/* ["prime256v1", "X9.62/SECG curve over a 256 bit prime field"], */
/* ["sect113r1", "SECG curve over a 113 bit binary field"], */
/* ["sect113r2", "SECG curve over a 113 bit binary field"], */
/* ["sect131r1", "SECG/WTLS curve over a 131 bit binary field"], */
/* ["sect131r2", "SECG curve over a 131 bit binary field"], */
/* ["sect163k1", "NIST/SECG/WTLS curve over a 163 bit binary field"], */
/* ["sect163r1", "SECG curve over a 163 bit binary field"], */
/* ["sect163r2", "NIST/SECG curve over a 163 bit binary field"], */
/* ["sect193r1", "SECG curve over a 193 bit binary field"], */
/* ["sect193r2", "SECG curve over a 193 bit binary field"], */
/* ["sect233k1", "NIST/SECG/WTLS curve over a 233 bit binary field"], */
/* ["sect233r1", "NIST/SECG/WTLS curve over a 233 bit binary field"], */
/* ["sect239k1", "SECG curve over a 239 bit binary field"], */
/* ["sect283k1", "NIST/SECG curve over a 283 bit binary field"], */
/* ["sect283r1", "NIST/SECG curve over a 283 bit binary field"], */
/* ["sect409k1", "NIST/SECG curve over a 409 bit binary field"], */
/* ["sect409r1", "NIST/SECG curve over a 409 bit binary field"], */
/* ["sect571k1", "NIST/SECG curve over a 571 bit binary field"], */
/* ["sect571r1", "NIST/SECG curve over a 571 bit binary field"], */
/* ["c2pnb163v1", "X9.62 curve over a 163 bit binary field"], */
/* ["c2pnb163v2", "X9.62 curve over a 163 bit binary field"], */
/* ["c2pnb163v3", "X9.62 curve over a 163 bit binary field"], */
/* ["c2pnb176v1", "X9.62 curve over a 176 bit binary field"], */
/* ["c2tnb191v1", "X9.62 curve over a 191 bit binary field"], */
/* ["c2tnb191v2", "X9.62 curve over a 191 bit binary field"], */
/* ["c2tnb191v3", "X9.62 curve over a 191 bit binary field"], */
/* ["c2pnb208w1", "X9.62 curve over a 208 bit binary field"], */
/* ["c2tnb239v1", "X9.62 curve over a 239 bit binary field"], */
/* ["c2tnb239v2", "X9.62 curve over a 239 bit binary field"], */
/* ["c2tnb239v3", "X9.62 curve over a 239 bit binary field"], */
/* ["c2pnb272w1", "X9.62 curve over a 272 bit binary field"], */
/* ["c2pnb304w1", "X9.62 curve over a 304 bit binary field"], */
/* ["c2tnb359v1", "X9.62 curve over a 359 bit binary field"], */
/* ["c2pnb368w1", "X9.62 curve over a 368 bit binary field"], */
/* ["c2tnb431r1", "X9.62 curve over a 431 bit binary field"], */
/* ["wap-wsg-idm-ecid-wtls1", "WTLS curve over a 113 bit binary field"], */
/* ["wap-wsg-idm-ecid-wtls3", "NIST/SECG/WTLS curve over a 163 bit binary field"], */
/* ["wap-wsg-idm-ecid-wtls4", "SECG curve over a 113 bit binary field"], */
/* ["wap-wsg-idm-ecid-wtls5", "X9.62 curve over a 163 bit binary field"], */
/* ["wap-wsg-idm-ecid-wtls6", "SECG/WTLS curve over a 112 bit prime field"], */
/* ["wap-wsg-idm-ecid-wtls7", "SECG/WTLS curve over a 160 bit prime field"], */
/* ["wap-wsg-idm-ecid-wtls8", "WTLS curve over a 112 bit prime field"], */
/* ["wap-wsg-idm-ecid-wtls9", "WTLS curve over a 160 bit prime field"], */
/* ["wap-wsg-idm-ecid-wtls10", "NIST/SECG/WTLS curve over a 233 bit binary field"], */
/* ["wap-wsg-idm-ecid-wtls11", "NIST/SECG/WTLS curve over a 233 bit binary field"], */
/* ["wap-wsg-idm-ecid-wtls12", "WTLS curve over a 224 bit prime field"], */
/* ["Oakley-EC2N-3", "\n\tIPSec/IKE/Oakley curve #3 over a 155 bit binary field.\n\tNot suitable for ECDSA.\n\tQuestionable extension field!"], */
/* ["Oakley-EC2N-4", "\n\tIPSec/IKE/Oakley curve #4 over a 185 bit binary field.\n\tNot suitable for ECDSA.\n\tQuestionable extension field!"], */
/* ["brainpoolP160r1", "RFC 5639 curve over a 160 bit prime field"], */
/* ["brainpoolP160t1", "RFC 5639 curve over a 160 bit prime field"], */
/* ["brainpoolP192r1", "RFC 5639 curve over a 192 bit prime field"], */
/* ["brainpoolP192t1", "RFC 5639 curve over a 192 bit prime field"], */
/* ["brainpoolP224r1", "RFC 5639 curve over a 224 bit prime field"], */
/* ["brainpoolP224t1", "RFC 5639 curve over a 224 bit prime field"], */
/* ["brainpoolP256r1", "RFC 5639 curve over a 256 bit prime field"], */
/* ["brainpoolP256t1", "RFC 5639 curve over a 256 bit prime field"], */
/* ["brainpoolP320r1", "RFC 5639 curve over a 320 bit prime field"], */
/* ["brainpoolP320t1", "RFC 5639 curve over a 320 bit prime field"], */
/* ["brainpoolP384r1", "RFC 5639 curve over a 384 bit prime field"], */
/* ["brainpoolP384t1", "RFC 5639 curve over a 384 bit prime field"], */
/* ["brainpoolP512r1", "RFC 5639 curve over a 512 bit prime field"], */
/* ["brainpoolP512t1", "RFC 5639 curve over a 512 bit prime field"], */
/* ["SM2", "SM2 curve over a 256 bit prime field"]] */


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

/* void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps); */

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

/* openssl ecparam -list_curves */



/*
 * The following function is a dummy one; replace it for
 * your C function definitions.
 */

/* TODO Debug Print */
void dp(const char * s)
{
    printf("%s\n", s);
    fflush(stdout);
}

ScmObj test_jwtec(void)
{
    return SCM_MAKE_STR("jwtec is working");
}

ScmObj test_ecdsa(void)
{
    ECDSA_SIG * sig = ECDSA_SIG_new();

    EC_KEY * key = EC_KEY_new();

    BIGNUM * bn1 = BN_new();
    unsigned char *s = "\377";
    unsigned char s2[256];

    BN_bin2bn(s, 2, bn1);

    int len = BN_bn2bin(bn1, s2);
    /* fprintf(stdout, "len: %d", len); */
    /* BN_print_fp(stdout, bn1); */

    BN_clear_free(bn1);

    EC_KEY_free(key);

    ECDSA_SIG_free(sig);

    EC_builtin_curve curves[2048];
    size_t crv_len = EC_get_builtin_curves(NULL, 0);

    printf("curve length: %d\n", crv_len);

    if (!EC_get_builtin_curves(curves, crv_len)) {
	printf("unable get curves\n");
    }
	
    int i = 0;
    EC_builtin_curve * curve = curves;

    while (i < crv_len)
    {
	const char * comment = curve->comment;
	const int nid = curve->nid;
	
	printf("nid: %d Comment: %s", nid, comment);

	const char * name = EC_curve_nid2nist(nid);

	printf(" NIST name: %s", name);
	
	const char * ln = OBJ_nid2ln(nid);
	printf(" LN: %s", ln);

	const char * sn = OBJ_nid2sn(nid);
	printf(" SN: %s", sn);


	printf("\n");

	curve++;
	i++;
    }

    printf("name: %s -> id: %d\n", "P-256", EC_curve_nist2nid("P-256"));
    printf("name: %s -> id: %d\n", "P-384", EC_curve_nist2nid("P-384"));
    printf("name: %s -> id: %d\n", "P-521", EC_curve_nist2nid("P-521"));
    

    fflush(stdout);
    
    return SCM_MAKE_STR("HOGEあいうえお");
}
    
BIGNUM * ScmUVectorToBignum(const ScmUVector * v)
{
    BIGNUM * bn = BN_new();
    const unsigned char *body = (unsigned char*)SCM_UVECTOR_ELEMENTS(v);
    const int len = SCM_UVECTOR_SIZE(v);

    BN_bin2bn(body, len, bn);

    return bn;
}

void CopyToU8vector(ScmUVector * v, int from, char * x, int size)
{
printf("from: %d to: %d\n", from, from + size);

    for (int src = 0; src < size; src++) {
	int dst = src + from;

printf("%x", x[src]);
fflush(stdout);
	Scm_UVectorSet(v, SCM_UVECTOR_U8, dst, Scm_MakeIntegerU(x[src]), SCM_CLAMP_ERROR);
    }
}

ScmObj ECSignatureToVectors(const ECDSA_SIG * signature)
{
    BIGNUM * r = NULL, * s = NULL;
    
    ECDSA_SIG_get0(signature, (const BIGNUM**)&r, (const BIGNUM**)&s);
    
    /* TODO scm_new or any? */
    char * R = SCM_NEW_ARRAY(char, 2048);
    char * S = SCM_NEW_ARRAY(char, 2048);

    int sizeR = BN_bn2bin(r, R);
    int sizeS = BN_bn2bin(s, S);

    ScmObj scm_r = Scm_MakeUVector(SCM_CLASS_U8VECTOR, sizeR, R);
    ScmObj scm_s = Scm_MakeUVector(SCM_CLASS_U8VECTOR, sizeS, S);

    /* CopyToU8vector(v, 0, R, sizeR); */
    /* CopyToU8vector(v, sizeR, S, sizeS); */

    ScmObj result = Scm_Values2(scm_r, scm_s);

exit:
    if (r != NULL) BN_free(r);
    if (s != NULL) BN_free(s);

    return result;
}

ScmObj verifyByKey(const char *curveType, const ScmUVector *DGST,
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
dp("1");
    const int nid = EC_curve_nist2nid(curveType);
    pubKey = EC_KEY_new_by_curve_name(nid);

dp("2");
    /* x, y seems non changed const values */
    if (! EC_KEY_set_public_key_affine_coordinates(pubKey, (BIGNUM*)x, (BIGNUM*)y)) {
	errorMsg = "Failed to set public key";
	goto exit;
    }

dp("3");
    signature = ECDSA_SIG_new();

    r = ScmUVectorToBignum(R);
    s = ScmUVectorToBignum(S);

dp("4");
    /* TODO check result */
    ECDSA_SIG_set0(signature, r, s);

    const int sigSize = ECDSA_size(pubKey);
    const char * dgst = (char*)SCM_UVECTOR_ELEMENTS(DGST);
    const int dgstlen = SCM_UVECTOR_SIZE(DGST);
    const int verifyResult = ECDSA_do_verify(dgst, dgstlen, signature, pubKey);
    
dp("5");
    if (! verifyResult) {
dp("5.1");
	result = SCM_FALSE;
	goto exit;
    }
    
dp("6");
    result = SCM_TRUE;

exit:
dp("7");
    /* TODO when not initialized, what value is ? */
    if (pubKey != NULL) EC_KEY_free(pubKey);
dp("8");
    if (x != NULL) BN_free(x);
    if (y != NULL) BN_free(y);
dp("10");
    if (r != NULL) BN_free(r);
dp("11");
    if (s != NULL) BN_free(s);
dp("12");
/* TODO */
    /* if (signature != NULL) ECDSA_SIG_free(signature); */
dp("13");

    if (errorMsg != NULL) {
	Scm_Error(errorMsg);
    }

    return result;
}

/* TODO curveType: accept nist / sn */

ScmObj signWithKey(const char * curveType, const ScmUVector * DGST, const ScmUVector * PRV)
{
    char * errorMsg = NULL;
    EC_KEY * privKey = NULL;
    BIGNUM * prv = NULL;

    prv = ScmUVectorToBignum(PRV);

    /* TODO curve */
    /* "P-256" "P-384" "P-521" */
    const int nid = EC_curve_nist2nid(curveType);
    /* TODO OBJ_sn2nid */

    /* TODO reconsider */
    if (nid <= 0) {
	errorMsg = "CurveType not found.";
	goto exit;
    }

    privKey = EC_KEY_new_by_curve_name(nid);

    EC_KEY_set_asn1_flag(privKey, OPENSSL_EC_NAMED_CURVE);
    EC_KEY_set_conv_form(privKey, POINT_CONVERSION_UNCOMPRESSED);

    /* TODO BN_is_zero when prv is zero eternal loop? */
printf("PRV: ");
BN_print_fp(stdout, prv);
fflush(stdout);
    if (! EC_KEY_set_private_key(privKey, prv)) {
	errorMsg = "Failed to set private key";
	goto exit;
    }

    const int sigSize = ECDSA_size(privKey);
printf("sigSize: %d\n", sigSize);
fflush(stdout);

    /* TODO malloc? */
    unsigned char sig[1024];
    unsigned int siglen;
    const char * dgst = (char *)SCM_UVECTOR_ELEMENTS(DGST);
    const int dgstlen = SCM_UVECTOR_SIZE(DGST);
printf("DGSTLEN: %d\n", dgstlen);
fflush(stdout);
    /* const int signResult = ECDSA_sign(0, dgst, dgstlen, sig, &siglen, privKey); */

/* printf("SIGLEN: %d\n", siglen); */
/* fflush(stdout); */

    /* if (! signResult) { */
    /* 	errorMsg = "Failed to sign by private key"; */
    /* 	goto exit; */
    /* } */

/* printf("SIG: %s\n", sig); */
/* fflush(stdout); */

    /* ScmObj result = Scm_MakeString(sig, siglen, siglen, SCM_STRING_COPYING); */

    const ECDSA_SIG * signature = ECDSA_do_sign(dgst, dgstlen, privKey);

    if (signature == NULL) {
	errorMsg = "Failed to sign by private key";
	goto exit;
    }

    ScmObj result = SCM_OBJ(ECSignatureToVectors(signature));

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
