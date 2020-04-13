;;;
;;; ECDSA module for JWT
;;;

(define-module jwt.ecdsa
  (use rfc.base64)
  (use rfc.sha1)
  (use gauche.uvector)
  (use util.match)
  (export
   call-test

   call-test-ecdsa
   ;; rsa-hasher decode-rsa rsa-sha

   ;; Like rfc.hmac library
   <ecdsa> ecdsa-update! ecdsa-final! ecdsa-digest ecdsa-digest-string

   ;; TODO hide
   do-sign do-verify
   )
  )
(select-module jwt.ecdsa)

;; Loads extension (To use Openssl libssl)
(dynamic-load "jwtec")

(define-class <ecdsa> ()
  ((key :getter key-of)
   (hasher :getter hasher-of)))

;;;
;;; Testing Scheme <-> C
;;;


(define (call-test-ecdsa)
  #?= (test-ecdsa)

  #?= (test-pass-arg "ABCDあいうえお" #u8(1 2 5 100 128))
  )

(define (call-test)
  #?= "Calling stub proc"
  #?= (test-jwteclib)
  #?= "Calling entry C proc"
  #?= (test-jwtec)
  )

;; TODO consideration
;; Scheme <=> C
;; <number> <=> <u8vector> <=> OctetString 
;; 
;; like hmac-digest interface


(define-method initialize ((self <ecdsa>) initargs)
  (next-method)
  (let-keywords initargs
      ([key #f]
       [hasher #f]
       ;; [block-size #f]
       )
    ;; TODO
    ))

(define-method ecdsa-update! ((self <ecdsa>) data)
  (digest-update! (hasher-of self) data))

(define-method ecdsa-final! ((self <ecdsa>))
  (let* ((v (string->u8vector (key-of self)))
         (opad (u8vector->string (u8vector-xor v #x5c)))
         (inner (digest-final! (hasher-of self)))
         (outer (digest-string (class-of (hasher-of self))
                               (string-append opad inner))))
    outer))

(define (ecdsa-digest . args)
  (let1 ecdsa (apply make <ecdsa> args)
    (generator-for-each
     (cut ecdsa-update! ecdsa <>)
     (cut read-block 4096))
    (ecdsa-final! ecdsa)))

(define (ecdsa-digest-string string . args)
  (with-input-from-string string
    (cut apply ecdsa-digest args)))

