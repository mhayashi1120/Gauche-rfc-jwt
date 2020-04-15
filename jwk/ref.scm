(define-module jwk.ref
  (use srfi-13)
  (use rfc.base64)
  (use util.match)
  (use gauche.uvector)
  (export-all))
(select-module jwk.ref)

;;;
;;; OctetString <-> Gauche integer
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

(define (bignum-ref key item)
  (b64->bignum (assoc-ref key item)))

(define (base64-urlencode s)
  (string-trim-right (base64-encode-string s :line-width #f :url-safe #t) #[=]))

(define (base64-urldecode s)
  (base64-decode-string s :url-safe #t))
