;;;
;;; Part of JWK (RFC7517)
;;;

(define-module jwk.ref
  (use srfi-13)
  (use rfc.base64)
  (use util.match)
  (use gauche.uvector)
  (export-all))
(select-module jwk.ref)

;;;
;;; Base64
;;;

(define (base64-urlencode s)
  (string-trim-right (base64-encode-string s :line-width #f :url-safe #t) #[=]))

(define (base64-urldecode s)
  ;; Decoder simply ignore trailing "="
  (base64-decode-string s :url-safe #t))

;;;
;;; OctetString <-> Gauche type
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
  (let1 b (base64-urldecode s)
    (string->bignum b)))

;;;
;;; Utility function
;;;

(define (bignum-ref item key :optional (option? #f))
  (cond
   [(assoc-ref item key) =>
    (^ [b64]
      (b64->bignum b64))]
   [(not option?)
    (error "Not found a key ~a" key)]
   [else #f]))

