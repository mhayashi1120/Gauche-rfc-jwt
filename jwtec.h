/*
 * jwtec.h
 */

/* Prologue */
#ifndef GAUCHE_JWTEC_H
#define GAUCHE_JWTEC_H

#include <gauche.h>
#include <gauche/extend.h>

SCM_DECL_BEGIN

// typedef struct ScmECDSASignRec {
//   SCM_HEADER;
//   ECDSA_SIG *sign;
// } ScmECDSASign;

// SCM_CLASS_DECL(Scm_ECDSASignClass);
// #define SCM_CLASS_ECDSA_SIGN (&Scm_ECDSASignClass)
// #define SCM_ECDSA_SIGN(obj) ((ScmECDSASign*)(obj))
// #define SCM_ECDSA_SIGN_P(obj) (SCM_XTYPEP(obj, SCM_CLASS_ECDSA_SIGN))

// extern ScmObj Scm_MakeFcgxStream(FCGX_Stream *stream);
// extern ScmObj Scm_MakePortWithFcgxStream(FCGX_Stream *stream);


/*
 * The following entry is a dummy one.
 * Replace it for your declarations.
 */

extern ScmObj doSign(ScmString * curveType, const ScmUVector * DGST, const ScmUVector * PRV);

extern ScmObj doVerify(ScmString * curveType, const ScmUVector *DGST,
		const ScmUVector *R, const ScmUVector *S,
		const ScmUVector *X, const ScmUVector *Y);

extern ScmObj getBuiltinCurves();

/* Epilogue */
SCM_DECL_END

#endif  /* GAUCHE_JWTEC_H */
