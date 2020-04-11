(define-module jwt.ecdsa
  (use rfc.base64)
  (use rfc.sha1)
  (use gauche.uvector)
  (use util.match)
  (export
   ;; rsa-hasher decode-rsa rsa-sha
   )
  )
(select-module jwt.ecdsa)

;; Loads extension (TODO Other algorithm)
(dynamic-load "jwtec")

;;;
;;; ECDSA module for JWT
;;;

