/*
 * jwtec.h
 */

/* Prologue */
#ifndef GAUCHE_JWTEC_H
#define GAUCHE_JWTEC_H

#include <gauche.h>
#include <gauche/extend.h>

SCM_DECL_BEGIN

extern ScmObj doSign(ScmString * curveType, const ScmUVector * DGST, const ScmUVector * PRV);

extern ScmObj doVerify(ScmString * curveType, const ScmUVector *DGST,
		const ScmUVector *R, const ScmUVector *S,
		const ScmUVector *X, const ScmUVector *Y);

/* Epilogue */
SCM_DECL_END

#endif  /* GAUCHE_JWTEC_H */
