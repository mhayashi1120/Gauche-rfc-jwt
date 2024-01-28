(use rfc.jwt)

(let ([header (construct-jwt-header)]
      [payload (construct-jwt-payload :iss "https://example.com/")])
  (jwt-encode header payload "our-hmac-secret"))

(jwt-decode
 "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tLyIsImlhdCI6MTU4NzcwMTU5Nn0.n6BABzuaYzTvpBRcIPs4uAggrh3_mVqqfeaJdgge-gI"
 "our-hmac-secret"
 :verify-payload? #t)

(jwt-verify
 '(("typ" . "JWT") ("alg" . "HS256"))
 '(("iss" . "https://example.com/") ("iat" . 1587701596))
 :iss "https://example.com/")
