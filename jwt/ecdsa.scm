;;;
;;; ECDSA module for JWT
;;;

(define-module jwt.ecdsa
  (use rfc.base64)
  (use rfc.sha1)
  (use gauche.uvector)
  (use jwk.ref)
  (use util.match)
  (export
   ;; rsa-hasher decode-rsa rsa-sha

   list-builtin-curves

   ecdsa-sign ecdsa-verify

   <ecdsa-private-key> <ecdsa-public-key>
   read-jwk-private read-jwk-public
   )
  )
(select-module jwt.ecdsa)

;; Loads extension (To use Openssl libssl)
(dynamic-load "jwtec")

(define-class <ecdsa-private-key> ()
  (
   (curve-name :init-keyword :curve-name)
   (hasher :init-keyword :hasher)
   (D :init-keyword :D)
   ))

(define-class <ecdsa-public-key> ()
  (
   (curve-name :init-keyword :curve-name)
   (hasher :init-keyword :hasher)
   ;; TODO
   (X :init-keyword :X)
   (Y :init-keyword :Y)
   ))

;;;
;;; TODO Scheme <-> C
;;;

(define (ensure-curve-name)
  )

(define (read-jwk-private jwk-node)
  (make <ecdsa-private-key>
    ;; TODO
    :curve-name "P-256"
    :hasher <sha256>
    :D (bignum-ref jwk-node "d")))

(define (read-jwk-public jwk-node)
  (make <ecdsa-public-key>
    ;; TODO
    :curve-name "P-256"
    :hasher <sha256>
    :X (bignum-ref jwk-node "x")
    :Y (bignum-ref jwk-node "y")))

(define (ecdsa-verify public-key signing-input signature)
  (let* ([digest (string->u8vector (digest-string (~ public-key'hasher) signing-input))])
    ;; TODO split
    (receive (r s) (values (string->u8vector (string-copy signature 0 (/ (string-length signature) 2)))
                           (string->u8vector (string-copy signature (/ (string-length signature) 2))))
      (do-verify (~ public-key 'curve-name)
                 digest r s
                 (bignum->u8vector (~ public-key'X))
                 (bignum->u8vector (~ public-key'Y))))))

(define (ecdsa-sign private-key signing-input)
  (let* ([digest (digest-string (~ private-key'hasher) signing-input)])
    (receive (r s) (do-sign (~ private-key 'curve-name) (string->u8vector digest) (bignum->u8vector (~ private-key'D)))
      (u8vector->string (u8vector-concatenate (list r s))))))


