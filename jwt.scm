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
  (use jwk.ref)
  (export

   construct-jwt-header construct-jwt-payload

   jwt-encode jwt-decode)
  )
(select-module jwt)

;; This module just contains hmac digest algorithm ("HS256", "HS384", "HS512", and "none")
;; Other algorithm (`Recommended`, `Optionali`) dynamically loaded after detect
;; algorithm from JWT header.

;; RSA algorithm is just `recommended`
(autoload jwt.rsa rsa-sign rsa-verify?)

;; ECDSA algorithm is marked as `recommended+`
(autoload jwt.ecdsa ecdsa-sign ecdsa-verify?)

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

(define (hmac-sign s key algorithm)
  (let1 hasher (hmac-hasher algorithm)
    (hmac-digest-string s :key key :hasher hasher)))

(define (hmac-verify? algorithm key header/b64 payload/b64 sign)
  (let* ([verify-target #"~|header/b64|.~|payload/b64|"]
         [verifier (hmac-sign verify-target key algorithm)])
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
     (hmac-sign target key algorithm)]
    ["none"
     (none-sign)]
    ;; These algorithm just `recommended`
    [(or "RS256" "RS384" "RS512")
     (rsa-sign algorithm target key)]
    [(or "ES256" "ES384" "ES512")
     (ecdsa-sign algorithm target key)]
    [else
     (errorf "Not yet supported algorithm ~a" algorithm)]))

(define (verify? algorithm key header/b64 payload/b64 sign)
  (match algorithm
    [(or "HS256" "HS384" "HS512")
     (hmac-verify? algorithm key header/b64 payload/b64 sign)]
    ["none"
     #f]
    [(or "RS256" "RS384" "RS512")
     (rsa-verify? algorithm key header/b64 payload/b64 sign)]
    [(or "ES256" "ES384" "ES512")
     (ecdsa-verify? algorithm key header/b64 payload/b64 sign)]))

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
 
;;;
;;; Encode / Decode (verify)
;;;

;; HEADER: json-object / STRING
;; PAYLOAD: json-object / STRING
;; KEY: Hold key depend on algorithm
(define (jwt-encode header payload key)
  (define (as-json x)
    (cond
     [(string? x) (parse-json-string x)]
     [(pair? x) x]))

  ;; ALGORITHM: "HS256" / "HS384" / "HS512" / "none"
  ;;        "RS256" "RS384" "RS512"
  (let* ([header/json (as-json header)]
         [algorithm (assoc-ref header/json "alg")]
         [header/b64 (encode-part header)]
         [payload/b64 (encode-part payload)]
         [sign-target #"~|header/b64|.~|payload/b64|"]
         [sign (signature algorithm sign-target key)]
         [sign/b64 (base64-urlencode sign)])
    #"~|sign-target|.~|sign/b64|"))

(define (jwt-decode token key :key (verify-signature? #t))
  (match (string-split token ".")
    [(header/b64 payload/b64 sign/b64)
     ;;TODO algorithm is not supplied
     (let* ([header (decode-part header/b64)]
            [algorithm (assoc-ref header "alg")]
            [payload (decode-part payload/b64)]
            [sign (base64-urldecode sign/b64)])
       (when verify-signature?
         (cond
          [(not algorithm)
           (error "Algorithm not detected")]
          [(verify? algorithm key header/b64 payload/b64 sign)]
          [else
           (errorf "Not a valid signature")]))
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