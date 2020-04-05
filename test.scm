;;;
;;; Test jwt
;;;

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
  (receive (header payload) (jwt-decode token secret :verify? #t)
    (test* "header1" header1 header)
    (test* "payload1" payload1 payload)
    ))

;; If you don't want `gosh' to exit with nonzero status even if
;; the test fails, pass #f to :exit-on-failure.
(test-end :exit-on-failure #t)




