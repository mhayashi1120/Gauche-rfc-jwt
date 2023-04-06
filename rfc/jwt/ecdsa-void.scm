;;;
;;; ECDSA module for JWT
;;;

(define-module rfc.jwt.ecdsa
  (export
   ecdsa-sign ecdsa-verify?
   )
  )
(select-module rfc.jwt.ecdsa)

(define (ecdsa-sign algorithm target key)
  (error "Not supported the algorithm"))

(define (ecdsa-verify? algorithm signing-input sign key)
  (error "Not supported the algorithm"))
