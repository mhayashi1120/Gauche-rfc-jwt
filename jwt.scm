;;;
;;; jwt
;;;

(define-module jwt
  (use srfi-13)
  (use util.match)
  (use rfc.sha1)
  (use rfc.json)
  (use rfc.hmac)
  (use rfc.base64)
  (export

   construct-jwt-header construct-jwt-payload

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
  ;; TODO
  (digest-string hasher s))

;;;
;;; Decoder / Encoder
;;;

(define (encode-header header)
  ($ base64-urlencode $ construct-json-string header))

(define (decode-header header/b64)
  ($ parse-json-string $ base64-urldecode header/b64))

(define (encode-payload payload)
  ($ base64-urlencode $ construct-json-string payload))

(define (decode-payload payload/b64)
  ($ parse-json-string $ base64-urldecode payload/b64))

;;;
;;; RSA (should be split other module)
;;;



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
  ;; ALGORITHM: "HS256" / "HS384" / "HS512" / "none"
  (let* ([algorithm (assoc-ref header "alg")]
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
         (let* ([verify-target #"~|header/b64|.~|payload/b64|"]
                [sign (base64-urldecode sign/b64)]
                [verifier (signature algorithm verify-target key)]
                [verifier/b64 (base64-urlencode verifier)])
           (unless (string=? sign verifier)
             (errorf "Not a valid signature expected ~a but ~a"
                     verifier/b64 sign/b64))))
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