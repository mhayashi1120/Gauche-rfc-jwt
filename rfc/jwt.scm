;;;
;;; rfc.jwt
;;;

(define-module rfc.jwt
  (use gauche.uvector)
  (use srfi-13)
  (use util.match)
  (use rfc.sha1)
  (use rfc.json)
  (use rfc.hmac)
  (use rfc.base64)
  (use rfc.jwk.ref)
  (export

   construct-jwt-header construct-jwt-payload

   jwt-encode jwt-decode jwt-verify)
  )
(select-module rfc.jwt)

;; This module just contains hmac digest algorithm ("HS256", "HS384", "HS512")
;;  and "none" . "HS256" and "none" algorithm is required by RFC7519.
;; Other algorithm (`Recommended`, `Optionali`) dynamically loaded after detect
;; by JWT header.

;; RSA algorithm is just `recommended`
(autoload rfc.jwt.rsa rsa-sign rsa-verify?)

;; ECDSA algorithm is marked as `recommended+`
(autoload rfc.jwt.ecdsa ecdsa-sign ecdsa-verify?)

;;;
;;; Decoder / Encoder
;;;

(define (ensure-json-construction x)
  (cond
   [(string? x) x]
   [(pair? x) (construct-json-string x)]))

(define (encode-part header)
  ($ base64-urlencode $ ensure-json-construction header))

(define (decode-part header/b64)
  ($ parse-json-string $ base64-urldecode header/b64))

;;;
;;; HMAC
;;;

(define (hmac-sign algorithm s key)
  (let1 hasher (hmac-hasher algorithm)
    (hmac-digest-string s :key key :hasher hasher)))

(define (hmac-verify? algorithm signing-input sign key)
  (let1 verifier (hmac-sign algorithm signing-input key)
    (equal? sign verifier)))

(define (hmac-hasher algorithm)
  (match algorithm
    ["HS256" <sha256>]
    ["HS384" <sha384>]
    ["HS512" <sha512>]
    [else #f]))

;;;
;;; none
;;;

(define (none-sign . _)
  "")

;;;
;;; Sign
;;;

(define (signature algorithm target key)
  (match algorithm
    [(or "HS256" "HS384" "HS512")
     (hmac-sign algorithm target key)]
    ["none"
     (none-sign)]
    ;; These algorithm just `recommended`
    [(or "RS256" "RS384" "RS512")
     (rsa-sign algorithm target key)]
    [(or "ES256" "ES384" "ES512")
     (ecdsa-sign algorithm target key)]
    [else
     (errorf "Not a supported algorithm ~a" algorithm)]))

(define (verify? algorithm key header/b64 payload/b64 sign)
  (let1 signing-input #"~|header/b64|.~|payload/b64|"
    (match algorithm
      [(or "HS256" "HS384" "HS512")
       (hmac-verify? algorithm signing-input sign key)]
      ["none"
       #f]
      [(or "RS256" "RS384" "RS512")
       (rsa-verify? algorithm signing-input sign key)]
      [(or "ES256" "ES384" "ES512")
       (ecdsa-verify? algorithm signing-input sign key)]
      [else
       (errorf "Not a supported algorithm ~a" algorithm)])))

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

;; ## Construct JWT header
;; -> <json>
(define (construct-jwt-header
         :key (typ "JWT") (cty #f) (alg "HS256")
         :allow-other-keys _other-keys)
  (cond-list
   [typ (cons "typ" typ)]
   [cty (cons "cty" cty)]
   [alg (cons "alg" alg)]
   [#t @ (other-keys _other-keys)]))

;; ## Construct JWT payload
;; -> <json>
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

(define (validate-claims-type payload)
  (define (NumericDate? x)
    (and (integer? x)
         (positive? x)))

  (map
   (match-lambda
    [(claim validator? valid-name)
     (and-let1 v (assoc-ref payload claim)
       (unless (validator? v)
         (errorf "Claim ~a should be ~a"
                 claim valid-name)))])
   `(
     ("iss" ,string? "StringOrURI")
     ("sub" ,string? "StringOrURI")
     ("aud" ,string? "StringOrURI")
     ("exp" ,NumericDate? "NumericDate")
     ("nbf" ,NumericDate? "NumericDate")
     ("iat" ,NumericDate? "NumericDate")
     ("jti" ,string? "String")
     )))
 
;;;
;;; Encode / Decode (and verify)
;;;

;; ## Encode as JWT
;; - HEADER: <json> | <string>
;; - PAYLOAD: <json> | <string>
;; - KEY: <top> Hold key depend on algorithm.
;; -> <string>
(define (jwt-encode header payload key)
  (define (as-json x)
    (cond
     [(string? x) (parse-json-string x)]
     [(pair? x) x]
     [else
      (error "Not a supported type of json" (class-of x))]))

  (let* ([header/json (as-json header)]
         [algorithm (assoc-ref header/json "alg")]
         [header/b64 (encode-part header)]
         [payload/b64 (encode-part payload)]
         [sign-target #"~|header/b64|.~|payload/b64|"]
         [sign (signature algorithm sign-target key)]
         [sign/b64 (base64-urlencode sign)])
    #"~|sign-target|.~|sign/b64|"))

;; ## Decode JWT
;; KEY can be #f if `verify-signature?` keyword is #f
;; If caller need `kid` in JWT header call with KEY as #f and `:verify-signature?` #f
;;  then get header (and `kid`) and call again this method with the correct key 
;;  correspond with `kid` to verify the TOKEN.
;; - TOKEN : <string>
;; - KEY : <top> Key depend on algorithm
;; -> [HEADER:<json> PAYLOAD:<json>]
(define (jwt-decode token key
                    :key (verify-signature? #t) (validate-type? #t)
                    ;; This check same as `jwt-verify` procedure's default
                    (verify-payload? #f))

  (assume-type token <string>)
  
  (match (string-split token ".")
    [(header/b64 payload/b64 sign/b64)
     (let* ([header (decode-part header/b64)]
            [algorithm (assoc-ref header "alg")]
            [payload (decode-part payload/b64)]
            [sign (base64-urldecode sign/b64)])
       (when verify-signature?
         (cond
          [(not algorithm)
           (error "Algorithm not detected.")]
          [(not key)
           (error "No key is supplied to verify signature.")]
          [(verify? algorithm key header/b64 payload/b64 sign)]
          [else
           (errorf "Not a valid signature")]))
       ;; all of Registered Claims are Optional
       (when validate-type?
         (validate-claims-type payload))
       (when verify-payload?
         (jwt-verify header payload))
       (values header payload))]
    [else
     (errorf "Invalid Json Web Token ~a"
             token)]))

;; ## Verify JWT
;; - HEADER : <json>
;; - PAYLOAD : <json>
;; -> <boolean>
(define (jwt-verify
         header payload
         :key
         ;; These are string value
         (iss #f) (aud #f)
         ;; Two argument (jti payload) procedure and must return boolean
         (jti #f)
         ;; This come from ruby
         (global-leeway 0)
         (exp-leeway #f) (nbf-leeway #f)
         (now (sys-time)))

  ;; EXP < now <= NBF
  ;; - Check expire, not-before via NOW
  (when now
    (and-let* ([p-exp (assoc-ref payload "exp")]
               [(<= p-exp (- now (or exp-leeway global-leeway 0)))])
      (errorf "Already expired at ~a"
              p-exp))
  
    (and-let* ([p-nbf (assoc-ref payload "nbf")]
               [(> p-nbf (+ now (or nbf-leeway global-leeway 0)))])
      (errorf "Must not be before at ~a"
              p-nbf))

    (and-let* ([p-iat (assoc-ref payload "iat")]
               [(> p-iat now)])
      (errorf "Must issue-at before now (~a) but ~a"
              now p-iat)))

  (and-let* ([iss]
             [p-iss (assoc-ref payload "iss")]
             [(not (string=? iss p-iss))])
    (errorf "Issuer not valid ~a"
            p-iss))

  (and-let* ([aud]
             [p-aud (assoc-ref payload "aud")]
             [(not (string=? aud p-aud))])
    (errorf "Audience not valid ~a"
            p-aud))
  #t)
