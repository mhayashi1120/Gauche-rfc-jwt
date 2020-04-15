
(use rfc.sha1)
(use util.digest)
(use gauche.uvector)
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

(define (bignum->u8vector n)
  ((with-module jwt.rsa bignum->u8vector) n))

(define (read-jwk-private json-node)
  (make <ecdsa-private-key>
    :D (bignum-ref json-node "d")))

(define (read-jwk-public json-node)
  (make <ecdsa-public-key>
    :X (bignum-ref json-node "x")
    :Y (bignum-ref json-node "y")))


(let* ([jwk-key (read-json "tests/rfc7515-a-3-jwkkey.json")]
       [header (read-json "tests/rfc7515-a-3-header.json")]
       ;; RFC sample contains newline and some spaces.
       [payload (file->string "tests/rfc7515-a-3-payload.json")]
       [privKey (read-jwk-private jwk-key)]
       [signingInput "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"]
       ;; [token (jwt-encode header payload privKey)]
       [dgst (string->u8vector (digest-string <sha256> signingInput))])

    (receive (r s)  #?= (do-sign "P-256" dgst (bignum->u8vector (~ privKey'D)))
             (with-output-to-file "/home/masa/tmp/hoge.der"
               (^[] (write-uvector r)
                 (write-uvector s)))

    (let* (;; [s #?= (list->u8vector (iota 32 1))]
           [pubKey (read-jwk-public jwk-key)]
           )
      
      #?= (do-verify "P-256" dgst r s (bignum->u8vector (~ pubKey'X)) (bignum->u8vector (~ pubKey'Y)))
      ;; (test* "Described in RFC Appendix A.3"
      ;;        (file->string "tests/rfc7515-a-3-result.txt") token)
      )))

;; If you don't want `gosh' to exit with nonzero status even if
;; the test fails, pass #f to :exit-on-failure.
(test-end :exit-on-failure #t)
