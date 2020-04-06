;;;
;;; jwt
;;;

(define-module jwt
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

;;
;; Put your Scheme definitions here
;;

(define (encode-base64 s)
  (base64-encode-string s :line-width #f :url-safe #t))

(define (decode-base64 s)
  (base64-decode-string s :url-safe #t))

(define (hmac-sha s key hasher)
  (hmac-digest-string s :key key :hasher hasher))

(define (encode-header header)
  (encode-base64
   (construct-json-string header)))

(define (decode-header header/b64)
  (let1 json (parse-json-string (decode-base64 header/b64))
    (values (assoc-ref json "alg") json)))

(define (encode-payload payload)
  (encode-base64 (construct-json-string payload)))

(define (decode-payload payload/b64)
  (parse-json-string (decode-base64 payload/b64)))

(define (hmac-hasher algorithm)
  (match algorithm
    ["HS256" <sha256>]
    ["HS384" <sha384>]
    ["HS512" <sha512>]
    [else #f]))

(define (signature algorithm target secret)
  (match algorithm
    ;; FIXME redundant pattern?
    [(and (? hmac-hasher)
          (= hmac-hasher hasher))
     (hmac-sha target secret hasher)]
    [else
     (errorf "Not yet supported algorithm ~a" algorithm)]))

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
 
(autoload srfi-13 string-pad-right)

(define (ensure-base64-suffix b64)
  (receive (d m) (div-and-mod (string-length b64) 4)
    (if (= m 0)
      b64
      (string-pad-right b64 (* (+ d 1) 4) #\=))))

(define (jwt-encode header payload secret)
  ;; ALGORITHM: "HS256" / "HS384" / "HS512" / "none" (TODO)
  (let* ([algorithm (assoc-ref header "alg")]
         [header/b64 (encode-header header)]
         [payload/b64 (encode-payload payload)]
         [sign-target #"~|header/b64|.~|payload/b64|"]
         [sign (signature algorithm sign-target secret)]
         [sign/b64 (encode-base64 sign)])
    #"~|sign-target|.~|sign/b64|"))

(define (jwt-decode token secret :key (verify? #f) (verify-signature? #t) (now (sys-time)))
  (match (string-split token ".")
    [(header/b64 payload/b64 sign/b64)
     (receive (algorithm header) (decode-header header/b64)
       (let* ([payload (decode-payload payload/b64)])
         (when (or verify-signature? verify?)
           (when verify-signature?
             (let* ([sign-target #"~|header/b64|.~|payload/b64|"]
                    [verifier (signature algorithm sign-target secret)]
                    [verifier/b64 (encode-base64 verifier)])
               (unless (string=? (ensure-base64-suffix sign/b64) verifier/b64)
                 (errorf "Not a valid signature expected ~a but ~a"
                         verifier/b64 sign/b64))))
           ;; TODO currently just verify signature.
           )
         (values header payload)))]
    [else
     (error "Invalid Json Web Token ~a"
            token)]))

