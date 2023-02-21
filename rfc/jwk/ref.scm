;;;
;;; Part of JWK (RFC7517)
;;;

(define-module rfc.jwk.ref
  (use srfi-13)
  (use rfc.base64)
  (use util.match)
  (use gauche.uvector)
  (export-all))
(select-module rfc.jwk.ref)

;;;
;;; Base64
;;;

;; ## <string> -> <string>
(define (base64-urlencode s)
  ($ (cut string-trim-right <> #[=])
     $ base64-encode-string s :line-width #f :url-safe #t))

;; ## <string> -> <string>
(define (base64-urldecode s)
  ;; Decoder simply ignore trailing "="
  (base64-decode-string s :url-safe #t))

;;;
;;; OctetString <-> Gauche type
;;;

;; ## <u8vector> -> <integer>
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

;; ## <string> -> <integer>
(define (string->bignum s)
  (u8vector->bignum
   (if (string-incomplete? s)
     (string->u8vector s)
     ;;TODO suspicious
     ($ list->u8vector $ map char->integer $ string->list s))))

;; ## <integer> -> <string>
(define (bignum->string n)
  ($ u8vector->string $ bignum->u8vector n))

;; ## <integer> -> <u8vector>
(define (bignum->u8vector n)
  (let loop ([i n]
             [l '()])
    (cond
     [(zero? i) (list->u8vector l)]
     [else
      (loop (ash i -8) (cons (logand #xff i) l))])))

;; ## <string> -> <integer>
(define (b64->bignum s)
  ($ string->bignum
     $ base64-urldecode s))

;;;
;;; Utility function
;;;

;; ##
;; -> <integer> | #f
(define (bignum-ref item key :optional (option? #f))
  (cond
   [(assoc-ref item key) =>
    (^ [b64]
      (b64->bignum b64))]
   [(not option?)
    (error "Not found a key ~a" key)]
   [else #f]))

