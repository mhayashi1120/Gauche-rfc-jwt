;;;
;;; Test jwt
;;;

(use file.util)
(use rfc.json)
(use gauche.test)

(test-start "rfc.jwk")
(use rfc.jwk.ref)
(test-module 'rfc.jwk.ref)

(test-end :exit-on-failure #t)

(test-start "rfc.jwt")
(use rfc.jwt)
(test-module 'rfc.jwt)

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
    )

  ;; This scenario concern:
  ;; 1. unknown algorithm yet (e.g. HS256 | ES256 | RS256) cannot decide KEY.
  ;; 2. KEY as #f and :verify-signature? #f to read header and payload.
  ;; 3. detect "alg" parameter from header.
  ;; 4. read requested algorithm KEY beforehand exchanged.
  ;; 5. call again `jwt-decode` with above KEY and verify.
  (receive (header payload) (jwt-decode token #f :verify-signature? #f)
    (test* "header1 non-verified and no-key" header1 header)
    (test* "payload1 non-verified and no-key" payload1 payload)
    )
  )

(let* ([secret #f]
       [header1 (construct-jwt-header :alg "none")]
       [payload1 (construct-jwt-payload)]
       [token (jwt-encode header1 payload1 secret)])
  ;; Working when secret is #f and :verify-signature? is off
  (receive (header payload) (jwt-decode token secret :verify-signature? #f)
    (test* "header1" header1 header)
    (test* "payload1" payload1 payload)

  (test* "Raise error when none algorithm" (test-error)
         (jwt-decode token secret))))

(test* "simple verify" #t
       (jwt-verify
        (construct-jwt-header)
        (construct-jwt-payload)))

(test* "exp verify fail expired" (test-error)
       (jwt-verify
        (construct-jwt-header)
        (construct-jwt-payload
         :exp 1587100001
         :iat 1586000000)
        :now 1587100001))

(test* "exp verify fail expired2" (test-error)
       (jwt-verify
        (construct-jwt-header)
        (construct-jwt-payload
         :exp 1587100000
         :iat 1586000000)
        :now 1587100001))

(test* "exp verify succeeded" #t
       (jwt-verify
        (construct-jwt-header)
        (construct-jwt-payload
         :exp 1587100002
         :iat 1586000000)
        :now 1587100001))

(test* "exp verify succeeded with leeway" #t
       (jwt-verify
        (construct-jwt-header)
        (construct-jwt-payload
         :exp 1587100002
         :iat 1586000000)
        :now 1587100001
        :global-leeway 1))

(test* "nbf verify failed" (test-error)
       (jwt-verify
        (construct-jwt-header)
        (construct-jwt-payload
         :nbf 1587100002
         :iat 1586000000)
        :now 1587100001
        ))

(test* "nbf verify succeeded" #t
       (jwt-verify
        (construct-jwt-header)
        (construct-jwt-payload
         :nbf 1587100002
         :iat 1586000000)
        :now 1587100002
        ))

(test-end :exit-on-failure #t)

(test-start "rfc.jwt.rsa")
(use rfc.jwt.rsa)
(test-module 'rfc.jwt.rsa)

(define (read-json file)
  (with-input-from-file file parse-json))

(let* ([jwk-key (read-json "tests/rfc7515-a-2-private-key.json")]
       [header (read-json "tests/rfc7515-a-2-header.json")]
       ;; RFC sample contains newline and some spaces.
       [payload (file->string "tests/rfc7515-a-2-payload.json")]
       [privKey (read-rsa-private jwk-key)]
       [token (jwt-encode header payload privKey)])
  (test* "Described in RFC"
         (file->string "tests/rfc7515-a-2-result.txt") token))

;; If you don't want `gosh' to exit with nonzero status even if
;; the test fails, pass #f to :exit-on-failure.
(test-end :exit-on-failure #t)

(let ([optional-tests *argv*])
  (dolist (test optional-tests)
    (load test)))
