(define-module rfc.jwt.ecdsa
  (export
   ecdsa-sign ecdsa-verify?))
(select-module rfc.jwt.ecdsa)

(define (ecdsa-sign algorithm . _)
  (error "Not supported the algorithm" algorithm))

(define (ecdsa-verify? algorithm . _)
  (error "Not supported the algorithm" algorithm))
