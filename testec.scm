
(use gauche.test)

(test-start "jwtec")
(use jwt.ecdsa)
(test-module 'jwt.ecdsa)


;; If you don't want `gosh' to exit with nonzero status even if
;; the test fails, pass #f to :exit-on-failure.
(test-end :exit-on-failure #t)
