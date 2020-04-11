
(use gauche.test)

(test-start "jwt.ecdsa")
(use jwt.ecdsa)
(test-module 'jwt.ecdsa)

;; TODO remove it after debug
(debug-print-width #f)

(call-test)

;; If you don't want `gosh' to exit with nonzero status even if
;; the test fails, pass #f to :exit-on-failure.
(test-end :exit-on-failure #t)
