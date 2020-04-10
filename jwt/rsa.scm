(define-module jwt.rsa
  (use rfc.base64)
  (use rfc.sha1)
  (use gauche.uvector)
  (use util.match)
  (export
   <rsa-private> <rsa-public>

   rsa-hasher decode-rsa rsa-sha)
  )
(select-module jwt.rsa)

;;;
;;; RSA module for JWT
;;;

(define (u8vector->bignum v :optional (be? #f))
  (let1 lis (u8vector->list v)
    (when be?
      (set! lis (reverse! lis)))
    (let loop ([l lis]
               [res 0])
      (match l
        [() res]
        [(x . xs)
         (loop xs (logior (ash res 8) x))]))))

(define (string->bignum s)
  (u8vector->bignum
   (if (string-incomplete? s)
     (string->u8vector s)
     ($ list->u8vector $ map char->integer $ string->list s))))

(define (bignum->string n)
  ($ u8vector->string $ bignum->u8vector n))

(define (bignum->u8vector n)
  (let loop ([i n]
             [l '()])
    (cond
     [(zero? i) (list->u8vector l)]
     [else
      (loop (ash i -8) (cons (logand #xff i) l))])))

(define (b64->bignum s)
  (let1 b (base64-decode-string s :url-safe #t)
    (string->bignum b)))

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

(define (compute-keysize N)
  (ceiling->exact (log (+ N 1) 256)))

(define (rsa-sign M key)
  (let1 C (expt-mod M (rsa-exponent key) (~ key'N))
    C))

(define (rsa-verify C key hasher)
  (let1 M1 (expt-mod C (rsa-exponent key) (~ key'N))
    M1))

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


(define (decode-rsa algorithm key header/b64 payload/b64 sign)
  (let* ([hasher (rsa-hasher algorithm)]
         [verify-target #"~|header/b64|.~|payload/b64|"]
         [M0 (pkcs1-encode hasher verify-target (compute-keysize (~ key'N)))]
         [C (string->bignum sign)]
         [M1 (rsa-verify C key hasher)])
    (values M0 M1)))


(define (rsa-sha s key hasher)
  (let* ([M (pkcs1-encode hasher s (compute-keysize (~ key'N)))]
         [C (rsa-sign M key)]
         [S (bignum->string C)])
    S))

(define (rsa-hasher algorithm)
  (match algorithm
    ["RS256" <sha256>]
    ["RS384" <sha384>]
    ["RS512" <sha512>]
    [else #f]))

