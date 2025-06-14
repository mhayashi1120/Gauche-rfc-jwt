(use gauche.test)

(test-section "rfc.jwt.ecdsa")

(use util.match)
(use file.util)
(use rfc.json)
(use rfc.jwt.ecdsa)

(test-module 'rfc.jwt.ecdsa)

(use rfc.jwk.ref)

(define (read-json file)
  (with-input-from-file file parse-json))

(let* ([jwk-key (read-json "__tests__/data/rfc7515-a-3-jwkkey.json")]
       [header (read-json "__tests__/data/rfc7515-a-3-header.json")]
       ;; RFC sample contains newline and some spaces.
       [payload (file->string "__tests__/data/rfc7515-a-3-payload.json")]
       [privKey (read-ecdsa-private jwk-key)]
       [signingInput "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"]
       [pubKey (read-ecdsa-public jwk-key)])

  (let1 signature (ecdsa-sign "ES256" signingInput privKey)
    (test* #"Verify rfc example signature ~(base64-urlencode signature)" #t
           (ecdsa-verify? "ES256" signingInput signature pubKey)))

  (let ([invalid-signatures '(
                              "A"
                              ;; ref: http://www.cryptomathic.com/news-events/blog/explaining-the-java-ecdsa-critical-vulnerability
                              "\x00;" "\x00;\x00;"
                              )])
    (dolist (sig invalid-signatures)
      (test* #"Verify rfc example with invalid sign ~(base64-urlencode sig)" #f
             (ecdsa-verify? "ES256" signingInput sig pubKey))))
  )

;; Extra EC test for openssl Sample key
(let* ([jwk-key (read-json "__tests__/data/openssl-sample-jwkkey.json")]
       [header (read-json "__tests__/data/rfc7515-a-3-header.json")]
       [privKey (read-ecdsa-private jwk-key)]
       [signingInput "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"]
       [pubKey (read-ecdsa-public jwk-key)])

  (let1 signature (ecdsa-sign "ES256" signingInput privKey)
    (test* #"Verify rfc example signature ~(base64-urlencode signature)" #t
           (ecdsa-verify? "ES256" signingInput signature pubKey)))

  (let ([invalid-signatures '(
                              "A"
                              ;; ref: http://www.cryptomathic.com/news-events/blog/explaining-the-java-ecdsa-critical-vulnerability
                              "\x00;" "\x00;\x00;"
                              )])
    (dolist (sig invalid-signatures)
      (test* #"Verify rfc example with invalid sign ~(base64-urlencode sig)" #f
             (ecdsa-verify? "ES256" signingInput sig pubKey))))
  )

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
;; Above process is implemented in samples/import-pem

(let* ([jwk-key (read-json "__tests__/data/ruby-spec-certs-ec256-private.json")]
       [signingInput "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"]
       [privKey (read-ecdsa-private jwk-key)])
  (let1 signature (ecdsa-sign "ES256" signingInput privKey)
    (let* ([pubKey (read-ecdsa-public jwk-key)])
      (test* #"Verify ruby-cert ec256 signature ~(base64-urlencode signature)" #t
             (ecdsa-verify? "ES256" signingInput signature pubKey)))))

(let* ([jwk-key (read-json "__tests__/data/ruby-spec-certs-ec384-private.json")]
       [signingInput "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"]
       [privKey (read-ecdsa-private jwk-key)])
  (let1 signature (ecdsa-sign "ES384" signingInput privKey)
    (let* ([pubKey (read-ecdsa-public jwk-key)])
      (test* #"Verify ruby-cert ec384 signature ~(base64-urlencode signature)" #t
             (ecdsa-verify? "ES384" signingInput signature pubKey)))))

(let* ([jwk-key (read-json "__tests__/data/ruby-spec-certs-ec512-private.json")]
       [signingInput "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"]
       [privKey (read-ecdsa-private jwk-key)])
  (let1 signature (ecdsa-sign "ES512" signingInput privKey)
    (let* ([pubKey (read-ecdsa-public jwk-key)])
      (test* #"Verify ruby-cert ec512 signature ~(base64-urlencode signature)" #t
             (ecdsa-verify? "ES512" signingInput signature pubKey)))))
