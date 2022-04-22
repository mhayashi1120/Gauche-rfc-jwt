# Gauche-rfc-jwt

Support RFC7519 (JWT)

- HS256, HS384, HS512
- RS256, RS384, RS512
- ES256, ES384, ES512
- none

## Samples:

```scheme
(use rfc.jwt)

(let ([header (construct-jwt-header)]
      [payload (construct-jwt-payload :iss "https://example.com/")])
  (jwt-encode header payload "our-hmac-secret"))
```

```scheme
(use rfc.jwt)

(jwt-decode
 "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tLyIsImlhdCI6MTU4NzcwMTU5Nn0.n6BABzuaYzTvpBRcIPs4uAggrh3_mVqqfeaJdgge-gI"
 "our-hmac-secret"
 :verify-payload? #t)
```

Optionally you can validate the payload:

```scheme
(use rfc.jwt)

(jwt-verify
 '(("typ" . "JWT") ("alg" . "HS256"))
 '(("iss" . "https://example.com/") ("iat" . 1587701596))
 :iss "https://example.com/")
```


### Import PEM (Sample)

see ./samples/import-pem

### Firebase sample

[Verify ID Tokens &nbsp;|&nbsp; Firebase Documentation](https://firebase.google.com/docs/auth/admin/verify-id-tokens)

see ./samples/import-firebase

## Ref:

- https://jwt.io/
- https://github.com/jwt/ruby-jwt
- https://www.jnsa.org/seminar/pki-day/2011/data/02_kanaoka.pdf
- [RFC7519 (JWT)](https://tools.ietf.org/html/rfc7519)


- RFC7515 (JWS)
- RFC7516 (JWE)
- RFC7517 (JWK)
- RFC7518 (JWA)

## TODO

- Check ecdsa algorithm is correctly working with other library (ruby-jwt)
- add test ecdsa encode
