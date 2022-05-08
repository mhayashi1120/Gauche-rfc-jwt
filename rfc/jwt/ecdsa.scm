;;;
;;; ECDSA module for JWT
;;;

(define-module rfc.jwt.ecdsa
  (use rfc.base64)
  (use rfc.sha1)
  (use gauche.uvector)
  (use rfc.jwk.ref)
  (use util.match)
  (export
   ecdsa-sign ecdsa-verify?

   <ecdsa-private-key> <ecdsa-public-key>
   read-ecdsa-private read-ecdsa-public
   )
  )
(select-module rfc.jwt.ecdsa)

;; Loads extension (To use Openssl libssl)
(dynamic-load "rfc--jwtec")

;;;
;;; JWK / JWS
;;;

(define key-parameter-alist
  `(
    ["ES256" ,<sha256> "P-256" 32]
    ["ES384" ,<sha384> "P-384" 48]
    ["ES512" ,<sha512> "P-521" 66]
    ))

(define (find-keyparameter crv)
  (find
   (match-lambda [[_ _ c . _] (string=? crv c)])
   key-parameter-alist))

;;
;; Key
;;

(define-class <ecdsa-key> ()
  (
   (CRV :init-keyword :CRV)
   (hasher)
   (sign-size)
   ))

(define-class <ecdsa-private-key> (<ecdsa-key>)
  (
   (D :init-keyword :D)
   ))

(define-class <ecdsa-public-key> (<ecdsa-key>)
  (
   (X :init-keyword :X)
   (Y :init-keyword :Y)
   ))

(define-method initialize ((self <ecdsa-key>) initargs)
  (next-method)
  (let-keywords initargs
      ([CRV #f]
       . _)
    (match (find-keyparameter CRV)
      [(_ hasher _ size)
       (slot-set! self'hasher hasher)
       (slot-set! self'sign-size size)]
      [else
       (errorf "CurveType ~a not supported" CRV)])))

(define (ecdsa-key? jwk-node)
  (and-let* ([kty (assoc-ref jwk-node "kty")]
             [(string? kty)])
    (string=? kty "EC")))

(define (check-jwk-node jwk-node)
  (unless (ecdsa-key? jwk-node)
    (error "Not a valid key `kty` must be \"EC\"")))

(define (read-ecdsa-private jwk-node)
  (check-jwk-node jwk-node)
  (make <ecdsa-private-key>
    :CRV (assoc-ref jwk-node "crv")
    :D (bignum-ref jwk-node "d")))

(define (read-ecdsa-public jwk-node)
  (check-jwk-node jwk-node)
  (make <ecdsa-public-key>
    :CRV (assoc-ref jwk-node "crv")
    :X (bignum-ref jwk-node "x")
    :Y (bignum-ref jwk-node "y")))

(define (check-acceptable algorithm key)
  (let1 crv (~ key'CRV)
    (match (find-keyparameter crv)
      [(algo hasher . _)
       (unless (eq? hasher (~ key'hasher))
         (errorf "Curve: ~a Hasher: ~a could not collaborate with requested algorithm ~a"
                 crv (~ key'hasher) algorithm))
       (unless (string=? algo algorithm)
         (errorf "Requested ~a algorithm but not supported with the Curve: ~a"
                 algorithm crv))]
      [else
       (errorf "Not a supported curve ~a" crv)])))

(define (R&S signature)
  (define (->u8vector s :optional (start 0) (end #f))
    (string->u8vector (string-copy s start end)))
  (let1 pos (div (string-length signature) 2)
    (values (->u8vector signature 0 pos)
            (->u8vector signature pos))))

;;;
;;; JWT
;;;

(define (ecdsa-verify? algorithm signing-input signature public-key)
  (check-acceptable algorithm public-key)
  (let* ([digest (digest-string (~ public-key'hasher) signing-input)]
         [digest/bin (string->u8vector digest)]
         [x/bin (bignum->u8vector (~ public-key'X))]
         [y/bin (bignum->u8vector (~ public-key'Y))])
    (receive (r s) (R&S signature)
      (do-verify (~ public-key 'CRV)
                 digest/bin r s
                 x/bin y/bin))))

;; To concat R and S with same octet size.
(define (maybe-fill size src)
  (let1 vlen (u8vector-length src)
    (cond
     [(< size vlen)
      (error "Assert")]
     [(= vlen size)
      src]
     [else
      (rlet1 dst (make-u8vector size 0)
        (let* ([dstart (- size vlen)])
          (u8vector-copy! dst dstart src)))])))

(define (ecdsa-sign algorithm signing-input private-key)
  (check-acceptable algorithm private-key)
  (let* ([digest (digest-string (~ private-key'hasher) signing-input)]
         [digest/bin (string->u8vector digest)]
         [d/bin (bignum->u8vector (~ private-key'D))])
    (receive (r s) (do-sign (~ private-key'CRV) digest/bin d/bin)
      (let ([R (maybe-fill (~ private-key'sign-size) r)]
            [S (maybe-fill (~ private-key'sign-size) s)])
      (u8vector->string (u8vector-concatenate (list R S)))))))
