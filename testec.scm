
(use file.util)
(use rfc.json)
(use gauche.test)

(test-start "jwt.ecdsa")
(use jwt.ecdsa)
(test-module 'jwt.ecdsa)

;; TODO remove it after debug
(debug-print-width #f)

(call-test)

(call-test-ecdsa)

(define (read-json file)
  (with-input-from-file file parse-json))

(use jwt.rsa)
(define (bignum-ref key item)
  ((with-module jwt.rsa b64->bignum) (assoc-ref key item)))

(define (read-jwk-private json-node)
  (make <ecdsa-private>
    :N (bignum-ref json-node "n")
    :D (bignum-ref json-node "d")))


;; (let* ([jwk-key (read-json "tests/rfc7515-a-3-jwkkey.json")]
;;        [header (read-json "tests/rfc7515-a-3-header.json")]
;;        ;; RFC sample contains newline and some spaces.
;;        [payload (file->string "tests/rfc7515-a-3-payload.json")]
;;        [privKey (read-jwk-private jwk-key)]
;;        [token (jwt-encode header payload privKey)]
;;        )
;;   (test* "Described in RFC Appendix A.3"
;;          (file->string "tests/rfc7515-a-3-result.txt") token))

;; If you don't want `gosh' to exit with nonzero status even if
;; the test fails, pass #f to :exit-on-failure.
(test-end :exit-on-failure #t)
