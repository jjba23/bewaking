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
  #:use-module (ice-9 match)
  #:use-module (ice-9 format)
  #:use-module (ice-9 string-fun)
  #:use-module (srfi srfi-1)
  #:use-module (ice-9 iconv)
  #:use-module (ice-9 popen)
  #:use-module (ice-9 textual-ports)
  #:use-module (ice-9 rdelim)
  #:export (issue-token))

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
                                                               (if (symbol?
                                                                    token-id)
                                                                   (symbol->string
                                                                    token-id)
                                                                   token-id))
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
         (tt (syscall (format #f "echo '`~a' | base64 --wrap=0" token)))
         (e-t (syscall (format #f
                        "echo \"~a\" | openssl enc -aes256 -pbkdf2 -base64 -k ~a"
                        tt encryption-key)))
         (clean-ttt (string-replace-substring e-t "\n" "")))
    ;; (write token-data)
    clean-ttt))

(define (decode-token token)
  (let* ((d (syscall (format #f
                      "echo '~a' | openssl aes-256-cbc -d -pbkdf2 -a -k ~a"
                      token encryption-key)))
         
         (d-t (syscall (format #f "echo '~a' | base64 --decode" d)))

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
    (write t)
    (newline)
    (newline)
    (write d)
    (newline)
    (display (format #f
                     "
User ID: ~a 
User email: ~a 
Token ID: ~a
Token Expires at: ~a
Is token expired: ~a
"
                     (assoc-ref d
                                'user-id)
                     (assoc-ref d
                                'user-email)
                     (assoc-ref d
                                'token-id)

                     (assoc-ref d
                                'token-expires-at)
                     (> (current-time)
                        (assoc-ref d
                                   'token-expires-at))))))

(trial-run)

;; Every call made, we need to hit db and decrypt, which means a bit of performance hit, so we can cache this for 5 minutes for example, 
;; Once logged in, you get a token, you then use the token for every call, we cache auth oks for 5 minutes, we do not cache auth errs
;; After 5 min we will hit db again to check for permission.
;; This is separate from the token expiry time, which only when current-timestamp > token-expiry, then we need to log you out and you need to login again

;; Then we take that token data (in Lisp/Scheme) and serialize it to JSON, minify, base64 encode it, reverse it, encrypt with some cypher (use openssl?), base64 encode it
;; For decoding we base64 decode, decrypt it (use openssl?), reverse it, base64 decode it, and parse the JSON

