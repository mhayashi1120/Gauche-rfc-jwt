
(use util.match)
(use file.util)
(use rfc.json)
(use gauche.test)

(test-start "jwt.ecdsa")
(use jwt.ecdsa)
(test-module 'jwt.ecdsa)

(define (read-json file)
  (with-input-from-file file parse-json))

(test* "Get builtin curves" #f
       (list-builtin-curves)
       (^ [_ result] (pair? result)))

(let* ([jwk-key (read-json "tests/rfc7515-a-3-jwkkey.json")]
       [header (read-json "tests/rfc7515-a-3-header.json")]
       ;; RFC sample contains newline and some spaces.
       [payload (file->string "tests/rfc7515-a-3-payload.json")]
       [privKey (read-jwk-private jwk-key)]
       [signingInput "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"]
       )

  (let1 signature (ecdsa-sign "ES256" signingInput privKey)
    (let* ([pubKey (read-jwk-public jwk-key)])
      (match-let1 (header payload) (string-split signingInput ".")
        (test* "Verify signature" #t
               (ecdsa-verify? "ES256" pubKey header payload signature))))))

;; If you don't want `gosh' to exit with nonzero status even if
;; the test fails, pass #f to :exit-on-failure.
(test-end :exit-on-failure #t)
