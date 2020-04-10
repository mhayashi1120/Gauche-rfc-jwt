;;;
;;; jwt
;;;

(define-module jwt
  (use gauche.uvector)
  (use srfi-13)
  (use util.match)
  (use rfc.sha1)
  (use rfc.json)
  (use rfc.hmac)
  (use rfc.base64)
  (export

   construct-jwt-header construct-jwt-payload

   <rsa-private> <rsa-public>

   jwt-encode jwt-decode)
  )
(select-module jwt)

;; Loads extension (TODO Other algorithm)
;; (dynamic-load "jwt")

(autoload rfc.hmac hmac-digest)
(autoload srfi-13 string-pad-right)

;;;
;;; Basic
;;;

(define (base64-urlencode s)
  (string-trim-right (base64-encode-string s :line-width #f :url-safe #t) #[=]))

(define (base64-urldecode s)
  (base64-decode-string s :url-safe #t))

(define (hmac-sha s key hasher)
  (hmac-digest-string s :key key :hasher hasher))

(define (rsa-sha s key hasher)
  (let* ([M (pkcs1-encode hasher s (compute-keysize (~ key'N)))]
         [C (rsa-sign M key)]
         [S (bignum->string C)])
    S))

;;;
;;; Decoder / Encoder
;;;

(define (ensure-json-construction x)
  (cond
   [(string? x) x]
   [(pair? x) (construct-json-string x)]))

(define (encode-header header)
  ($ base64-urlencode $ ensure-json-construction header))

(define (decode-header header/b64)
  ($ parse-json-string $ base64-urldecode header/b64))

(define (encode-payload payload)
  ($ base64-urlencode $ ensure-json-construction payload))

(define (decode-payload payload/b64)
  ($ parse-json-string $ base64-urldecode payload/b64))

;;;
;;; RSA (should be split other module)
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

(define (b64->bignum s)
  (let1 b (base64-decode-string s :url-safe #t)
    (string->bignum b)))

(define (bignum->string n)
  ($ u8vector->string $ bignum->u8vector n))

(define (bignum->u8vector n)
  (let loop ([i n]
             [l '()])
    (cond
     [(zero? i) (list->u8vector l)]
     [else
      (loop (ash i -8) (cons (logand #xff i) l))])))

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

;;;
;;; Sign
;;;

(define (hmac-hasher algorithm)
  (match algorithm
    ["HS256" <sha256>]
    ["HS384" <sha384>]
    ["HS512" <sha512>]
    [else #f]))

(define (rsa-hasher algorithm)
  (match algorithm
    ["RS256" <sha256>]
    ["RS384" <sha384>]
    ["RS512" <sha512>]
    [else #f]))

(define (signature algorithm target key)
  (match algorithm
    ;; FIXME redundant pattern?
    [(and (? hmac-hasher)
          (= hmac-hasher hasher))
     (hmac-sha target key hasher)]
    [(and (? rsa-hasher)
          (= rsa-hasher hasher))
     (rsa-sha target key hasher)]
    ["none"
     ""]
    [else
     (errorf "Not yet supported algorithm ~a" algorithm)]))

;;;
;;; Verifier
;;;

(define (decode-hmac algorithm key header/b64 payload/b64 sign/b64)
  (let* ([verify-target #"~|header/b64|.~|payload/b64|"]
         [verifier (signature algorithm verify-target key)]
         [sign (base64-urldecode sign/b64)])
    (values sign verifier)))

(define (decode-rsa algorithm key header/b64 payload/b64 sign/b64)
  (let* ([hasher (rsa-hasher algorithm)]
         [verify-target #"~|header/b64|.~|payload/b64|"]
         [M0 (pkcs1-encode hasher verify-target (compute-keysize (~ key'N)))]
         [C (string->bignum (base64-urldecode sign/b64))]
         [M1 (rsa-verify C key hasher)])
    (values M0 M1)))

;;;
;;; Construct json
;;;

(define (other-keys keys)
  (let loop ([params keys]
             [res '()])
    (match params
      [()
       (reverse! res)]
      [((? keyword? k) v . rest)
       (loop rest
             (cons
              (cons (keyword->string k) v)
              res))])))

(define (construct-jwt-header
         :key (typ "JWT") (cty #f) (alg "HS256")
         :allow-other-keys _other-keys)
  (cond-list
   [typ (cons "typ" typ)]
   [cty (cons "cty" cty)]
   [alg (cons "alg" alg)]
   [#t @ (other-keys _other-keys)]))

(define (construct-jwt-payload
         :key (iss #f) (sub #f) (aud #f)
         (exp #f) (nbf #f) (iat (sys-time)) (jti #f)
         :allow-other-keys _other-keys)
  (cond-list
   [iss (cons "iss" iss)]
   [sub (cons "sub" sub)]
   [aud (cons "aud" aud)]
   [exp (cons "exp" exp)]
   [nbf (cons "nbf" nbf)]
   [iat (cons "iat" iat)]
   [jti (cons "jti" jti)]
   [#t @ (other-keys _other-keys)]))
 
(define (jwt-encode header payload key)
  (define (as-json x)
    (cond
     [(string? x) (parse-json-string x)]
     [(pair? x) x]))

  ;; ALGORITHM: "HS256" / "HS384" / "HS512" / "none"
  ;;        "RS256" "RS384" "RS512"
  (let* ([header/json (as-json header)]
         [algorithm (assoc-ref header/json "alg")]
         [header/b64 (encode-header header)]
         [payload/b64 (encode-payload payload)]
         [sign-target #"~|header/b64|.~|payload/b64|"]
         [sign (signature algorithm sign-target key)]
         [sign/b64 (base64-urlencode sign)])
    #"~|sign-target|.~|sign/b64|"))

(define (jwt-decode token key :key (verify-signature? #t))
  (match (string-split token ".")
    [(header/b64 payload/b64 sign/b64)
     ;;TODO algorithm is not supplied
     (let* ([header (decode-header header/b64)]
            [algorithm (assoc-ref header "alg")]
            [payload (decode-payload payload/b64)])
       (when verify-signature?
         (receive (signature verifier)
             (match algorithm
               [(or "HS256" "HS384" "HS512")
                (decode-hmac algorithm key header/b64 payload/b64 sign/b64)]
               [(or "RS256" "RS384" "RS512")
                (decode-rsa algorithm key header/b64 payload/b64 sign/b64)]
               ["none"
                ;; TODO reconsider
                (values #f #f)])
           (unless (equal? signature verifier)
             (let1 verifier/b64 (base64-urlencode verifier)
               (errorf "Not a valid signature expected ~a but ~a"
                       verifier/b64 sign/b64)))))
       ;; TODO Check type (some of field has number or not)
       (values header payload))]
    [else
     (errorf "Invalid Json Web Token ~a"
             token)]))

;; TODO Implements just MUST 
(define (jwt-verify
         header payload
         :key
         (iss #f)
         (aud #f)
         (now (sys-time)))
  ;; TODO currently just verify signature.
  ;; - Check expire, via NOW
  (if-let1 exp (assoc-ref header "exp")
    (when (< exp now)
      (errorf "Already expired at ~a" exp)))

  )