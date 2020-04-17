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
   list-builtin-curves

   ecdsa-sign ecdsa-verify?

   <ecdsa-private-key> <ecdsa-public-key>
   read-ecdsa-private read-ecdsa-public
   )
  )
(select-module rfc.jwt.ecdsa)

;; Loads extension (To use Openssl libssl)
(dynamic-load "rfc--jwtec")

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

;;;
;;; JWK
;;;

(define-class <ecdsa-key> ()
  (
   (curve-name :init-keyword :curve-name)
   (hasher :init-keyword :hasher)
   (sign-size :init-keyword :sign-size)
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

(define (ecdsa-key? jwk-node)
  (and-let* ([kty (assoc-ref jwk-node "kty")]
             [(string? kty)])
    (string=? kty "EC")))

(define (read-key-parameters jwk-node)
  (unless (ecdsa-key? jwk-node)
    (error "Not a valid key `kty` must be \"EC\""))
  (if-let1 crv (assoc-ref jwk-node "crv")
    (match (find-keyparameter crv)
     [(_ hasher _ size)
      (values hasher crv size)]
     [else
      (errorf "CurveType ~a not supported" crv)])
    (error "CurveType `crv` not detected.")))

(define (read-ecdsa-private jwk-node)
  (receive (hasher curve-type size) (read-key-parameters jwk-node)
    (make <ecdsa-private-key>
      :curve-name curve-type
      :hasher hasher
      :sign-size size
      :D (bignum-ref jwk-node "d"))))

(define (read-ecdsa-public jwk-node)
  (receive (hasher curve-type size) (read-key-parameters jwk-node)
    (make <ecdsa-public-key>
      :curve-name curve-type
      :hasher hasher
      :sign-size size
      :X (bignum-ref jwk-node "x")
      :Y (bignum-ref jwk-node "y"))))

(define (check-acceptable algorithm key)
  (let1 crv (~ key'curve-name)
    (match (find-keyparameter crv)
      [(algo hasher . _)
       (unless (eq? hasher (~ key'hasher))
         (errorf "Curve: ~a Hasher: ~a is not collateral" crv (~ key'hasher)))
       (unless (string=? algo algorithm)
         (errorf "Request ~a algorithm but not supported with the Curve: ~a"
                 algorithm crv))]
      [else
       (errorf "Not a supported curve ~a" crv)])))

(define (R&S key signature)
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
    (receive (r s) (R&S public-key signature)
      (do-verify (~ public-key 'curve-name)
                 digest/bin r s
                 x/bin y/bin))))

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
    (receive (r s) (do-sign (~ private-key'curve-name) digest/bin d/bin)
      (let ([R (maybe-fill (~ private-key'sign-size) r)]
            [S (maybe-fill (~ private-key'sign-size) s)])
      (u8vector->string (u8vector-concatenate (list R S)))))))
