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
   list-builtin-curves

   ecdsa-sign ecdsa-verify?

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
   (X :init-keyword :X)
   (Y :init-keyword :Y)
   ))

;;;
;;; Scheme <-> C
;;;

(define (ecdsa-key? jwk-node)
  (and-let* ([kty (assoc-ref jwk-node "kty")]
             [(string? kty)])
    (string=? kty "EC")))

(define (read-key-parameters jwk-node)
  (unless (ecdsa-key? jwk-node)
    (error "Not a valid key `kty` must be \"EC\""))
  (if-let1 crv (assoc-ref jwk-node "crv")
    (match crv
     ["P-256"
      (values <sha256> crv)]
     ["P-384"
      (values <sha384> crv)]
     ["P-521"
      (values <sha512> crv)]
     [else
      (errorf "CurveType ~a not supported" crv)])
    (error "CurveType `crv` not detected.")))

(define (read-jwk-private jwk-node)
  (receive (hasher curve-type) (read-key-parameters jwk-node)
    (make <ecdsa-private-key>
      :curve-name curve-type
      :hasher hasher
      :D (bignum-ref jwk-node "d"))))

(define (read-jwk-public jwk-node)
  (receive (hasher curve-type) (read-key-parameters jwk-node)
    (make <ecdsa-public-key>
      :curve-name curve-type
      :hasher hasher
      :X (bignum-ref jwk-node "x")
      :Y (bignum-ref jwk-node "y"))))

(define (R&S key signature)
  (define (->u8vector s start :optional (end #f))
    (string->u8vector (string-copy s start end)))
  (let1 pos (/ (string-length signature) 2)
    (values (->u8vector signature 0 pos)
            (->u8vector signature pos))))

(define (ecdsa-verify? algorithm public-key header/b64 payload/b64 signature)
  (let* ([signing-input #"~|header/b64|.~|payload/b64|"]
         [digest (digest-string (~ public-key'hasher) signing-input)]
         [digest/bin (string->u8vector digest)]
         [x/bin (bignum->u8vector (~ public-key'X))]
         [y/bin (bignum->u8vector (~ public-key'Y))])
    (receive (r s) (R&S public-key signature)
      (do-verify (~ public-key 'curve-name)
                 digest/bin r s
                 x/bin y/bin))))

(define (ecdsa-sign algorithm signing-input private-key)
  (let* ([digest (digest-string (~ private-key'hasher) signing-input)]
         [digest/bin (string->u8vector digest)]
         [d/bin (bignum->u8vector (~ private-key'D))])
    (receive (r s) (do-sign (~ private-key 'curve-name) digest/bin d/bin)
      (u8vector->string (u8vector-concatenate (list r s))))))


