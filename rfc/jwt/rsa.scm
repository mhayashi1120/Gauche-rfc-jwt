;;;
;;; RSA module for JWT
;;;

(define-module rfc.jwt.rsa
  (use rfc.base64)
  (use rfc.sha1)
  (use gauche.uvector)
  (use util.match)
  (use rfc.jwk.ref)
  (export
   <rsa-private> <rsa-public>
   read-rsa-private read-rsa-public

   rsa-hasher rsa-verify? rsa-sign)
  )
(select-module rfc.jwt.rsa)

;;;
;;; RSA module for JWT
;;;

;;;
;;; Key
;;;

(define-class <rsa-public> ()
  (
   (N :init-keyword :N)
   (E :init-keyword :E :getter rsa-exponent)
   ))

(define-class <rsa-private> ()
  (
   (N :init-keyword :N)
   (D :init-keyword :D :getter rsa-exponent)
   ))

(define (read-rsa-private jwk-node)
  (make <rsa-private>
    :N (bignum-ref jwk-node "n")
    :D (bignum-ref jwk-node "d")))

(define (read-rsa-public jwk-node)
  (make <rsa-public>
    :N (bignum-ref jwk-node "n")
    :E (bignum-ref jwk-node "e")))

(define (compute-keysize N)
  (ceiling->exact (log (+ N 1) 256)))

;;;
;;; PKCS (Part of RFC 3447)
;;;

;; RFC 3447 9.2 EMSA-PKCS1-v1_5-ENCODE
(define (pkcs1-encode hasher m emLen)
  (let* ([H (digest-string hasher m)]
         [T (append
             (pkcs-digest-info hasher)
             ($ u8vector->list $ string->u8vector H))]
         [tLen (length T)]
         )
    (when (< emLen (+ tLen 11))
      (error "intended encoded message length too short"))
    (let* ([PS (make-list (- emLen tLen 3) #xff)]
           [EM `(#x00 #x01 ,@PS #x00 ,@T)])
      (u8vector->bignum (list->u8vector EM)))))

;; Gauche ext/tls/axTLS/ssl/x509.c
;; -> sig_prefix_sha256

;; RFC 3447 9.2 Notes
;; SHA-256: (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
;; SHA-384: (0x)30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30
;; SHA-512: (0x)30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40

;; SHA-256: "\x30;\x31;\x30;\x0d;\x06;\x09;\x60;\x86;\x48;\x01;\x65;\x03;\x04;\x02;\x01;\x05;\x00;\x04;\x20;"
;; SHA-384: "\x30;\x41;\x30;\x0d;\x06;\x09;\x60;\x86;\x48;\x01;\x65;\x03;\x04;\x02;\x02;\x05;\x00;\x04;\x30;"
;; SHA-512: "\x30;\x51;\x30;\x0d;\x06;\x09;\x60;\x86;\x48;\x01;\x65;\x03;\x04;\x02;\x03;\x05;\x00;\x04;\x40;"

(define (pkcs-digest-info hasher)
  (cond
   [(eq? <sha256> hasher)
    `(#x30 #x31 #x30 #x0d #x06 #x09 #x60 #x86 #x48 #x01
           #x65 #x03 #x04 #x02 #x01 #x05 #x00 #x04 #x20)]
   [(eq? <sha384> hasher)
    `(#x30 #x41 #x30 #x0d #x06 #x09 #x60 #x86 #x48 #x01
           #x65 #x03 #x04 #x02 #x02 #x05 #x00 #x04 #x30)]
   [(eq? <sha512> hasher)
    `(#x30 #x51 #x30 #x0d #x06 #x09 #x60 #x86 #x48 #x01
           #x65 #x03 #x04 #x02 #x03 #x05 #x00 #x04 #x40)]
   [else
    (error "Not a supported hasher" hasher)]))

;;;
;;; RSA
;;;

(define (rsa-encrypt M key)
  (expt-mod M (rsa-exponent key) (~ key'N)))

(define (rsa-decrypt C key hasher)
  (expt-mod C (rsa-exponent key) (~ key'N)))

;;;
;;; Sign / Verify
;;;

(define (rsa-verify? algorithm signing-input sign public-key)
  (let* ([hasher (rsa-hasher algorithm)]
         [M0 (pkcs1-encode hasher signing-input (compute-keysize (~ public-key'N)))]
         [C (string->bignum sign)]
         [M1 (rsa-decrypt C public-key hasher)])
    (equal? M0 M1)))

(define (rsa-sign algorithm s private-key)
  (let* ([hasher (rsa-hasher algorithm)]
         [M (pkcs1-encode hasher s (compute-keysize (~ private-key'N)))]
         [C (rsa-encrypt M private-key)]
         [S (bignum->string C)])
    S))

(define (rsa-hasher algorithm)
  (match algorithm
    ["RS256" <sha256>]
    ["RS384" <sha384>]
    ["RS512" <sha512>]
    [else #f]))

