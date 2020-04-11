(define-module jwt.ecdsa
  (use rfc.base64)
  (use rfc.sha1)
  (use gauche.uvector)
  (use util.match)
  (export
   call-test

   call-test-ecdsa
   ;; rsa-hasher decode-rsa rsa-sha
   )
  )
(select-module jwt.ecdsa)

;; Loads extension (Openssl libssl)
(dynamic-load "jwtec")

;;;
;;; ECDSA module for JWT
;;;

(define (call-test-ecdsa)
  (test-ecdsa))

(define (call-test)
  #?= "Calling stub proc"
  #?= (test-jwteclib)
  #?= "Calling entry C proc"
  #?= (test-jwtec)
  )

