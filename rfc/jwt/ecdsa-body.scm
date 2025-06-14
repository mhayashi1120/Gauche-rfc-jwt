(define-module rfc.jwt.ecdsa
  (use rfc.base64)
  (use rfc.sha1)
  (use gauche.uvector)
  (use rfc.jwk.ref)
  (use util.match)
  (export
   <ecdsa-public> <ecdsa-private>
   read-ecdsa-private read-ecdsa-public

   ecdsa-sign ecdsa-verify?)
  ;; To keep backward compat
  (export
   (rename <ecdsa-public> <ecdsa-public-key>)
   (rename <ecdsa-private> <ecdsa-private-key>)))
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
   ;; <string>
   (CRV :init-keyword :CRV)
   ;; <message-digest-algorithm>
   (hasher)
   ;; <integer>
   (sign-size)
   ))

(define-class <ecdsa-private> (<ecdsa-key>)
  (
   ;; <integer>
   (D :init-keyword :D)
   ))

(define-class <ecdsa-public> (<ecdsa-key>)
  (
   ;; <integer>
   (X :init-keyword :X)
   ;; <integer>
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
      [_
       (errorf "CurveType ~a not supported" CRV)])))

(define (ecdsa-key? jwk-node)
  (and-let* ([kty (assoc-ref jwk-node "kty")]
             [(string? kty)])
    (string=? kty "EC")))

(define (check-jwk-node jwk-node)
  (unless (ecdsa-key? jwk-node)
    (error "Not a valid key `kty` must be \"EC\"")))

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
      [_
       (errorf "Not a supported curve ~a" crv)])))

(define (R&S signature)
  (define (->u8vector s :optional (start 0) (end #f))
    (string->u8vector (string-copy s start end)))
  (let1 pos (div (string-length signature) 2)
    (values (->u8vector signature 0 pos)
            (->u8vector signature pos))))

;; To concat R and S with same octet size.
(define (%maybe-fill size src)
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

;;;
;;; # JWK API
;;;

;; ## -> <ecdsa-private>
(define (read-ecdsa-private jwk-node)
  (check-jwk-node jwk-node)
  (make <ecdsa-private>
    :CRV (assoc-ref jwk-node "crv")
    :D (bignum-ref jwk-node "d")))

;; ## -> <ecdsa-public>
(define (read-ecdsa-public jwk-node)
  (check-jwk-node jwk-node)
  (make <ecdsa-public>
    :CRV (assoc-ref jwk-node "crv")
    :X (bignum-ref jwk-node "x")
    :Y (bignum-ref jwk-node "y")))

;;;
;;; # JWT API
;;;

;; ## -> <boolean>
(define (ecdsa-verify? algorithm signing-input signature public-key)
  (check-acceptable algorithm public-key)
  (let* ([digest (digest-string (~ public-key'hasher) signing-input)]
         [digest/bin (string->u8vector digest)]
         [X (bignum->u8vector (~ public-key'X))]
         [Y (bignum->u8vector (~ public-key'Y))])
    (receive (R S) (R&S signature)
      (do-verify (~ public-key 'CRV)
                 digest/bin R S
                 X Y))))

;; ## -> <string>
(define (ecdsa-sign algorithm signing-input private-key)
  (check-acceptable algorithm private-key)
  (let* ([digest (digest-string (~ private-key'hasher) signing-input)]
         [digest/bin (string->u8vector digest)]
         [D (bignum->u8vector (~ private-key'D))])
    (receive (r s) (do-sign (~ private-key'CRV) digest/bin D)
      (let ([R (%maybe-fill (~ private-key'sign-size) r)]
            [S (%maybe-fill (~ private-key'sign-size) s)])
      (u8vector->string (u8vector-concatenate (list R S)))))))
