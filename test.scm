;;;
;;; Test jwt
;;;

(use gauche.test)

(test-start "jwt")
(use jwt)
(test-module 'jwt)

;; The following is a dummy test code.
;; Replace it for your tests.
(test* "test-jwt" "jwt is working"
       (test-jwt))

;; If you don't want `gosh' to exit with nonzero status even if
;; the test fails, pass #f to :exit-on-failure.
(test-end :exit-on-failure #t)




