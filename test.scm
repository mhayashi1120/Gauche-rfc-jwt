;;;
;;; Test jwt
;;;

(use file.util)
(use rfc.json)
(use gauche.test)

(test-start "jwt")
(use jwt)
(test-module 'jwt)

(test* "construct header"
       (construct-jwt-header :another "foo")
       `(("typ" . "JWT")
         ("alg" . "HS256")
         ("another" . "foo")))

(test* "construct payload"
       (construct-jwt-payload :iat 10 :another "foo")
       `(("iat" . 10)
         ("another" . "foo")))

(let* ([secret "HOGE"]
       [header1 (construct-jwt-header :alg "HS256")]
       [payload1 (construct-jwt-payload)]
       [token (jwt-encode header1 payload1 secret)])
  (receive (header payload) (jwt-decode token secret)
    (test* "header1" header1 header)
    (test* "payload1" payload1 payload)
    ))

(let* ([secret #f]
       [header1 (construct-jwt-header :alg "none")]
       [payload1 (construct-jwt-payload)]
       [token (jwt-encode header1 payload1 secret)])
  (receive (header payload) (jwt-decode token secret)
    (test* "header1" header1 header)
    (test* "payload1" payload1 payload)
    ))

(use jwt.rsa)
(test-module 'jwt.rsa)

(define (read-jwk-private json-node)
  (make <rsa-private>
    :N (bignum-ref json-node "n")
    :D (bignum-ref json-node "d")))

(define (read-jwk-public json-node)
  (make <rsa-public>
    :N (bignum-ref json-node "n")
    :E (bignum-ref json-node "e")))

(define (read-json file)
  (with-input-from-file file parse-json))

(define (bignum-ref key item)
  ((with-module jwt.rsa b64->bignum) (assoc-ref key item)))

(let* ([jwk-key (read-json "tests/rfc7515-a-2-private-key.json")]
       [header (read-json "tests/rfc7515-a-2-header.json")]
       ;; RFC sample contains newline and some spaces.
       [payload (file->string "tests/rfc7515-a-2-payload.json")]
       [privKey (read-jwk-private jwk-key)]
       [token (jwt-encode header payload privKey)])
  (test* "Described in RFC"
         (file->string "tests/rfc7515-a-2-result.txt") token))

;; If you don't want `gosh' to exit with nonzero status even if
;; the test fails, pass #f to :exit-on-failure.
(test-end :exit-on-failure #t)




