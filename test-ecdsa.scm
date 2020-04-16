
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
       [privKey (read-ecdsa-private jwk-key)]
       [signingInput "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"]
       )

  (let1 signature (ecdsa-sign "ES256" signingInput privKey)
    (let* ([pubKey (read-ecdsa-public jwk-key)])
      (test* #"Verify rfc example signature ~(base64-urlencode signature)" #t
             (ecdsa-verify? "ES256" signingInput signature pubKey)))))

;; Import from ruby-jwt (https://github.com/jwt/ruby-jwt)

;; 1. in the spec/fixtures/certs/:
;; openssl ec -text -in ec256-private.pem
;; openssl ec -text -in ec384-private.pem
;; openssl ec -text -in ec512-private.pem

;; 1-1-1. "pub:" section strip first 0x04 https://tools.ietf.org/html/rfc5480#section-2.2
;; 1-1-2. split the hex sequence to X and Y (just half of it)
;; 1-2. "priv:" section is D parameter.
;; 2. Generate JWK key.
;; 2-1. "kty" -> "EC" "crv" -> P-256 / P-384 / P-521
;; 2-2. "d", "x", "y" -> above
;; Above process is implemented in tests/import-pem

(let* ([jwk-key (read-json "tests/ruby-spec-certs-ec256-private.json")]
       [signingInput "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"]
       [privKey (read-ecdsa-private jwk-key)])
  (let1 signature (ecdsa-sign "ES256" signingInput privKey)
    (let* ([pubKey (read-ecdsa-public jwk-key)])
      (test* #"Verify ruby-cert ec256 signature ~(base64-urlencode signature)" #t
             (ecdsa-verify? "ES256" signingInput signature pubKey)))))

(let* ([jwk-key (read-json "tests/ruby-spec-certs-ec384-private.json")]
       [signingInput "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"]
       [privKey (read-ecdsa-private jwk-key)])
  (let1 signature (ecdsa-sign "ES384" signingInput privKey)
    (let* ([pubKey (read-ecdsa-public jwk-key)])
      (test* #"Verify ruby-cert ec384 signature ~(base64-urlencode signature)" #t
             (ecdsa-verify? "ES384" signingInput signature pubKey)))))

(let* ([jwk-key (read-json "tests/ruby-spec-certs-ec512-private.json")]
       [signingInput "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"]
       [privKey (read-ecdsa-private jwk-key)])
  (let1 signature (ecdsa-sign "ES512" signingInput privKey)
    (let* ([pubKey (read-ecdsa-public jwk-key)])
      (test* #"Verify ruby-cert ec512 signature ~(base64-urlencode signature)" #t
             (ecdsa-verify? "ES512" signingInput signature pubKey)))))

;; If you don't want `gosh' to exit with nonzero status even if
;; the test fails, pass #f to :exit-on-failure.
(test-end :exit-on-failure #t)
