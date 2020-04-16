#!/usr/bin/env gosh

(use rfc.json)
(use file.util)
(use jwk.ref)
(use jwt.ecdsa)

(define (read-json path)
  (let1 file (expand-path (build-path "~/data/src/Gauche-jwt/" path))
    (with-input-from-file file parse-json)))


(define (main args)
  (let* ([jwk-key (read-json "tests/ruby-spec-certs-ec512-private.json")]
         [privKey (read-jwk-private jwk-key)]
         [signingInput "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"]
         [pubKey (read-jwk-public jwk-key)]
         )
    #?= (let1 signature (base64-urldecode "AXn63VqgFmJkyo67uOB4wA-66YKqc194LAd4jMdjoIe99JCWQK4j5Ocm283kRjfvEKthOj0EkEgt8nn6Uf7_jzmxq24xV8bsvlMWapubTLFAiurhmOfqjUcMl3nRQvrzjFhAcgLWAX3WeionIbozpXr1_50Ohc4eMeaONdDl5qZqEKQ")
          #?= (ecdsa-verify? "ES512" signingInput signature pubKey))
    0))