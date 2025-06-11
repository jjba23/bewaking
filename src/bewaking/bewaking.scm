;; bewaking

;; Copyright © Josep Bigorra <jjbigorra@gmail.com>

;; bewaking is free software: you can redistribute it and/or modify
;; it under the terms of the Lesser GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; bewaking is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; Lesser GNU General Public License for more details.

;; You should have received a copy of the Lesser GNU General Public License
;; along with bewaking.  If not, see <https://www.gnu.org/licenses/>.

(define-module (bewaking bewaking)
  #:use-module (uuid generate)
  #:use-module (system foreign)
  #:use-module (rnrs)
    #:use-module (statprof)
  #:use-module (ice-9 match)
  #:use-module (ice-9 format)
  #:use-module (ice-9 string-fun)
  #:use-module (srfi srfi-1)
  #:use-module (ice-9 iconv)
  #:use-module (ice-9 popen)
  #:use-module (ice-9 textual-ports)
  #:use-module (ice-9 rdelim)
  #:export (issue-token))

(define %%clib
  (make-parameter (dynamic-link)))

(define-syntax define-c-function
  (lambda (x)
    (syntax-case x ()
                 ((_ type name)
                  (quasisyntax (module-define! (current-module)
                                               '(unsyntax (datum->syntax (syntax
                                                                          name)
                                                                         (symbol-append '%
                                                                          (syntax->datum
                                                                           (syntax
                                                                            name)))))
                                               (pointer->procedure type
                                                                   (dynamic-func
                                                                    (symbol->string 'name)
                                                                    (%%clib))
                                                                   '()
                                                                   #:return-errno?
                                                                   #t))))
                 ((_ type name
                     (para ...))
                  (quasisyntax (module-define! (current-module)
                                               '(unsyntax (datum->syntax (syntax
                                                                          name)
                                                                         (symbol-append '%
                                                                          (syntax->datum
                                                                           (syntax
                                                                            name)))))
                                               (pointer->procedure type
                                                                   (dynamic-func
                                                                    (symbol->string 'name)
                                                                    (%%clib))
                                                                   (list para
                                                                         ...)
                                                                   #:return-errno?
                                                                   #t)))))))

(define-syntax ffi-binding
  (syntax-rules ()
                ((_ () body ...)
                 (begin
                   body ... #t))
                ((_ libname body ...)
                 (parameterize ((%%clib (dynamic-link libname)))
                   body ... #t))))

(eval-when (eval load compile)
           ;; TODO ensure portability
           (ffi-binding "/run/current-system/profile/lib/nss/libnss3.so"
                        (define-c-function int NSS_NoDB_Init
                                           ('*))
                        (define-c-function int NSS_Init
                                           ('*))
                        (define-c-function int NSS_InitReadWrite
                                           ('*))
                        (define-c-function int NSS_IsInitialized)
                        (define-c-function int NSS_Initialize
                                           ('* '*
                                            '*
                                            '* uint32))
                        (define-c-function int NSS_Shutdown)
                        (define-c-function '* NSS_InitContext
                                           ('* '*
                                            '*
                                            '*
                                            '* uint32))
                        (define-c-function '* NSSBase64_DecodeBuffer
                                           ('* '*
                                            '* unsigned-int))
                        (define-c-function '* NSSBase64_EncodeItem
                                           ('* '* unsigned-int
                                            '*))
                        (define-c-function int PK11_HashBuf
                                           (int '*
                                                '* uint32)))

           ;; TODO ensure portability
           (ffi-binding "/run/current-system/profile/lib/nss/libssl3.so"
                        (define-c-function int SSL_OptionSet
                                           ('* uint32 int))
                        (define-c-function int SSL_ImportFD
                                           ('* int)))

           (ffi-binding "libnspr4"
                        (define-c-function void PR_Init
                                           (int int int))
                        (define-c-function int PR_ImportTCPSocket
                                           (int))
                        (define-c-function int PR_Write
                                           (int '* size_t))
                        (define-c-function int PR_Read
                                           (int '* size_t))
                        (define-c-function int PR_Close
                                           (int))
                        (define-c-function int PR_Cleanup)))

(define *SECItem*
  (list int uint64 unsigned-int))
(define* (make-sec-item #:optional (type 0)
                        (data 0)
                        (len 0))
  (make-c-struct *SECItem*
                 (list type data len)))

(define (base64-decode ibuf len)
  (let* ((ret (%NSSBase64_DecodeBuffer %null-pointer %null-pointer ibuf len)))
    (cond
      ((eq? ret %null-pointer)
       (throw 'artanis-err 500 nss:base64-decode
              "Invalid string to be decode to Base64!"))
      (else (let ((item (parse-c-struct ret *SECItem*)))
              (pointer->string (make-pointer (cadr item))
                               (caddr item)))))))

(define (base64-encode ibuf len)
  (let* ((addr (pointer-address ibuf))
         (item (make-sec-item 0 addr len))
         (ret (%NSSBase64_EncodeItem %null-pointer %null-pointer 0 item)))
    (cond
      ((eq? ret %null-pointer)
       (throw 'artanis-err 500 nss:base64-encode
              "Invalid string to be encoded to Base64!"))
      (else (pointer->string ret)))))

(define (nss:base64-encode str/bv)
  (nss:hash-it base64-encode str/bv))

(define (nss:base64-decode str/bv)
  (nss:hash-it base64-decode str/bv))

(define (nss:hash-it algo str/bv)
  (let ((in (cond
              ((string? str/bv)
               (string->pointer str/bv))
              (((@ (rnrs) bytevector?)
                str/bv)
               (bytevector->pointer str/bv))
              (else (throw 'artanis-err 500 nss:hash-it
                           "need string or bytevector!" str/bv))))
        (len (cond
               ((string? str/bv)
                (string-utf8-length str/bv))
               ((bytevector? str/bv)
                (bytevector-length str/bv))
               (else (throw 'artanis-err 500 nss:hash-it
                            "Invalid input type `~a'" str/bv)))))
    (algo in len)))

(define (syscall cmd)
  (let* ((process (open-input-pipe cmd))
         (process-output (get-string-all process)))
    (close-pipe process) process-output))

(define encryption-key
  "10d0670c-e79b-406e-a37b-926d7b804be0")

;; I had trouble getting it working using echo with -n. This worked for me:

;; To encrypt:

;; echo "PLAINTEXT_STRING" | openssl enc -aes256 -pbkdf2 -base64 -k <password>

;; you'll be prompted to provide a decryption password.

;; To decrypt:

;; echo "ENCRYPTED_STRING" | openssl aes-256-cbc -d -pbkdf2 -a -k <password>

(define* (issue-token #:key user-details-provider
                      (token-valid-seconds (* 60 60 48)))
  (let* ((token-id (generate-string-uuid))
         (now (current-time))
         (user-details (user-details-provider))
         (token-data `((token-type . bewaking-token) (token-id unquote
                                                               token-id)
                       (token-created-at unquote now)
                       (token-expires-at unquote
                                         (+ now token-valid-seconds))
                       (user-id unquote
                                (assoc-ref user-details
                                           'id))
                       (user-email unquote
                                   (assoc-ref user-details
                                              'email))
                       (user-name unquote
                                  (assoc-ref user-details
                                             'name))
                       (user-permissions unquote
                                         (assoc-ref user-details
                                                    'permissions))))
         (token (with-output-to-string (lambda ()
                                         (write token-data))))
         (tt (nss:base64-encode (format #f "'~a" token)))
         (ttt (string-replace-substring tt "\r\n" ""))
         (e-t (syscall (format #f
                        "echo \"~a\" | openssl enc -aes256 -pbkdf2 -base64 -k ~a"
                        ttt encryption-key)))
         (clean-ttt (string-replace-substring e-t "\n" "")))
    clean-ttt))

(define (decode-token token)
  (let* ((d (syscall (format #f
                      "echo \"~a\" | openssl aes-256-cbc -d -pbkdf2 -a -k ~a"
                      token encryption-key)))
         
         (d-t (nss:base64-decode d))
         (tt (eval-string d-t)))
    
    tt))

(define (trial-run)
  (let* ((start (current-time))
         (t (issue-token #:user-details-provider (lambda ()
                                                   `((id . "f421188e-3ca2-4d55-a65c-0278cd3f77b1")
                                                     (email . "jjbigorra@gmail.com")
                                                     (name . "Joe")
                                                     (permissions
                                                      bewaking:write
                                                      bewaking:read)))))
         (d (decode-token t))
         (end (current-time)))
    (display t)
    (newline)
    (newline)
    (display d)
    (newline)
    (display (format #f "\nUser ID: ~a | User email: ~a | Token Expires at: ~a"
                     (assoc-ref d 'user-id)
                     (assoc-ref d 'user-email)
                     (assoc-ref d 'token-expires-at)))
))

(trial-run)


;; Every call made, we need to hit db and decrypt, which means a bit of performance hit, so we can cache this for 5 minutes for example, 
;; Once logged in, you get a token, you then use the token for every call, we cache auth oks for 5 minutes, we do not cache auth errs
;; After 5 min we will hit db again to check for permission.
;; This is separate from the token expiry time, which only when current-timestamp > token-expiry, then we need to log you out and you need to login again

;; Then we take that token data (in Lisp/Scheme) and serialize it to JSON, minify, base64 encode it, reverse it, encrypt with some cypher (use openssl?), base64 encode it
;; For decoding we base64 decode, decrypt it (use openssl?), reverse it, base64 decode it, and parse the JSON

