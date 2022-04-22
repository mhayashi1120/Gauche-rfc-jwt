(use srfi-13)
(use gauche.process)
(use rfc.base64)
(use rfc.822)
(use www.cgi)
(use rfc.jwt)

(define (do-process->string cmd in)
  (let1 p (run-process
           cmd
           :redirects `((<< 0 ,in) (> 1 stdout))
           :wait #t)
    (port->string (process-output p 'stdout))))

(define (openssl-section-value output section)
  )

(define (pem-to-jwk algo pem)
  (cond
   [(string-prefix? "RS" algo)
    #?= (do-process->string `(openssl rsa -pubin -noout -text -in -) pem)]
   [(string-prefix? "ES" algo)
    #?= (do-process->string `(openssl ec -pubin -noout -text -in -) pem)]
   [else
    (error "Not supported")])
  (and-let* ([m (#/-+BEGIN PUBLIC KEY-+\n(.*)\n-+END PUBLIC KEY-+$/ pem)]
             [pub/b64 (m 1)]
             [der (base64-decode-string pub/b64)])
    #?= der
    #f))

;; copied from jwt.io "SHARE JWT" button
(define (try-jwtio-debugger algo uri :optional (supplied-key #f))
  (let* ([query (if-let1 m (#/\?(.*)$/ uri)
                  (cgi-parse-parameters :query-string (m 1) )
                  (error "TODO"))]
         [token (rfc822-header-ref query "token")]
         [pubKeyPem (rfc822-header-ref query "publicKey")])
    (jwt-decode token (or supplied-key
                          (pem-to-jwk algo pubKeyPem)))))

(debug-print-width #f)

;; HS256 (your-256-bit-secret)
#?= (try-jwtio-debugger "HS256" "https://jwt.io/#debugger-io?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" "your-256-bit-secret")

;; HS384 (your-384-bit-secret)
#?= (try-jwtio-debugger "HS384" "https://jwt.io/#debugger-io?token=eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.bQTnz6AuMJvmXXQsVPrxeQNvzDkimo7VNXxHeSBfClLufmCVZRUuyTwJF311JHuh" "your-384-bit-secret")

;; RS256
#?= (try-jwtio-debugger "RS256" "https://jwt.io/#debugger-io?token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA&publicKey=-----BEGIN%20PUBLIC%20KEY-----%0AMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv%0AvkTtwlvBsaJq7S5wA%2BkzeVOVpVWwkWdVha4s38XM%2Fpa%2Fyr47av7%2Bz3VTmvDRyAHc%0AaT92whREFpLv9cj5lTeJSibyr%2FMrm%2FYtjCZVWgaOYIhwrXwKLqPr%2F11inWsAkfIy%0AtvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0%0Ae%2Blf4s4OxQawWD79J9%2F5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb%0AV6L11BWkpzGXSW4Hv43qa%2BGSYOD2QU68Mb59oSk2OB%2BBtOLpJofmbGEGgvmwyCI9%0AMwIDAQAB%0A-----END%20PUBLIC%20KEY-----")


;; RS512
#?= (try-jwtio-debugger "RS512" "https://jwt.io/#debugger-io?token=eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.JlX3gXGyClTBFciHhknWrjo7SKqyJ5iBO0n-3S2_I7cIgfaZAeRDJ3SQEbaPxVC7X8aqGCOM-pQOjZPKUJN8DMFrlHTOdqMs0TwQ2PRBmVAxXTSOZOoEhD4ZNCHohYoyfoDhJDP4Qye_FCqu6POJzg0Jcun4d3KW04QTiGxv2PkYqmB7nHxYuJdnqE3704hIS56pc_8q6AW0WIT0W-nIvwzaSbtBU9RgaC7ZpBD2LiNE265UBIFraMDF8IAFw9itZSUCTKg1Q-q27NwwBZNGYStMdIBDor2Bsq5ge51EkWajzZ7ALisVp-bskzUsqUf77ejqX_CBAqkNdH1Zebn93A&publicKey=-----BEGIN%20PUBLIC%20KEY-----%0AMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv%0AvkTtwlvBsaJq7S5wA%2BkzeVOVpVWwkWdVha4s38XM%2Fpa%2Fyr47av7%2Bz3VTmvDRyAHc%0AaT92whREFpLv9cj5lTeJSibyr%2FMrm%2FYtjCZVWgaOYIhwrXwKLqPr%2F11inWsAkfIy%0AtvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0%0Ae%2Blf4s4OxQawWD79J9%2F5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb%0AV6L11BWkpzGXSW4Hv43qa%2BGSYOD2QU68Mb59oSk2OB%2BBtOLpJofmbGEGgvmwyCI9%0AMwIDAQAB%0A-----END%20PUBLIC%20KEY-----")


;; ES256
#?= (try-jwtio-debugger "ES256" "https://jwt.io/#debugger-io?token=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA&publicKey=-----BEGIN%20PUBLIC%20KEY-----%0AMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs%2Fo5%2BuQbTjL3chynL4wXgUg2R9%0Aq9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B%2BdFabmdT9POxg%3D%3D%0A-----END%20PUBLIC%20KEY-----")
