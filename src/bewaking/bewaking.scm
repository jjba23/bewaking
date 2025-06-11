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
  #:export (generate-token decrypt-token
                           unsafe-generate-token
                           string-garble
                           string-ungarble
                           unsafe-decrypt-token
                           token-payload-valid?))

(define (syscall cmd)
  (let* ((process (open-input-pipe cmd))
         (process-output (get-string-all process)))
    (close-pipe process) process-output))

(define (string-garble s)
  (let* ((len (string-length s))
         (mid-point (floor (/ len 2)))
         (first-half-original (substring s 0 mid-point))
         (second-half-original (substring s mid-point len))
         (first-half-reversed (string-reverse first-half-original))
         (second-half-reversed (string-reverse second-half-original)))
    (string-append second-half-reversed first-half-reversed)))

(define (string-ungarble s)
  (let* ((len (string-length s))
         (len-original-first-half (floor (/ len 2)))
         (len-original-second-half (- len len-original-first-half))
         (reversed-original-second-half (substring s 0
                                                   len-original-second-half))
         (reversed-original-first-half (substring s len-original-second-half
                                                  len))
         (original-second-half (string-reverse reversed-original-second-half))
         (original-first-half (string-reverse reversed-original-first-half)))
    (string-append original-first-half original-second-half)))

(define (token-payload-valid? token)
  (and (not (equal? #f
                    (assoc-ref token
                               'token-type)))
       (not (equal? #f
                    (assoc-ref token
                               'token-id)))
       (not (equal? #f
                    (assoc-ref token
                               'token-created-at)))
       (not (equal? #f
                    (assoc-ref token
                               'token-expires-at)))
       (not (equal? #f
                    (assoc-ref token
                               'owner-id)))
       (not (equal? #f
                    (assoc-ref token
                               'owner-name)))
       (not (equal? #f
                    (assoc-ref token
                               'owner-permissions)))))

(define* (unsafe-generate-token #:key encryption-key
                                (get-owner-details (lambda ()
                                                     '()))
                                (token-validity-seconds (* 72 3600)))
  "Generates a secure, encrypted, and Base64-encoded authentication token.

  This function creates a token containing owner details and timestamps, serializes it,
  and then uses external command-line tools to encrypt and encode it.

  WARNING: This implementation has a hard dependency on the `base64` and `openssl`
  command-line utilities being available in the system's PATH.

 #:key encryption-key:   The secret key (string) used for AES-256 encryption.
                          This parameter is required.
 #:key get-owner-details: A thunk (procedure with no arguments) that returns an
                          association list of the owner's details. Must include at
                          least an 'id' key.
 #:key token-validity-seconds: The token's lifetime in seconds.
                                Defaults to 72 hours.

  #:returns: An encrypted and Base64-encoded string representing the token."

  (let* ((owner-details (get-owner-details))
         (owner-id (assoc-ref owner-details
                              'id))
         (current-timestamp (current-time))
         (expiration-timestamp (+ current-timestamp token-validity-seconds))

         (payload `((token-type . bewaking-token) (token-id unquote
                                                            (generate-string-uuid))
                    (token-created-at unquote current-timestamp)
                    (token-expires-at unquote expiration-timestamp)
                    (owner-id unquote owner-id)
                    (owner-email unquote
                                 (assoc-ref owner-details
                                            'email))
                    (owner-name unquote
                                (assoc-ref owner-details
                                           'name))
                    (owner-permissions unquote
                                       (assoc-ref owner-details
                                                  'permissions))))
         (_ (unless (token-payload-valid? payload)
              (error "Could not generate token from given payload!")))

         ;; Serialize the payload into a string.
         (payload-string (with-output-to-string (lambda ()
                                                  (write payload))))

         ;; Base64 encode the payload string.
         ;; `echo -n` prevents a trailing newline. `--wrap=0` prevents line breaks.
         (base64-payload (syscall (format #f "echo -n '`~a' | base64 --wrap=0"
                                          payload-string)))

         ;; Encrypt the Base64 payload using OpenSSL.
         ;; -aes256: Specifies the AES-256 cipher.
         ;; -pbkdf2: Uses PBKDF2 to derive the key from the `encryption-key`.
         ;; -a -A: Base64-encodes the encrypted output for safe transport and all in 1 line.
         (encrypted-payload (syscall (format #f
                                      "echo -n '~a' | openssl enc -aes256 -pbkdf2 -a -A -k '~a'"
                                      base64-payload encryption-key)))

         ;; Clean the final token by removing any trailing whitespace from the
         ;; openssl output, producing the final token.
         (token (string-trim-right encrypted-payload)))
    
    (unless encryption-key
      (error
       "generate-token: The #:encryption-key keyword argument is required."))

    (unless owner-id
      (error
       "generate-token: Owner details from #:get-owner-details must contain an 'id'."))

    (string-garble token)))

(define* (unsafe-decrypt-token #:key token encryption-key)
  "Decodes and validates a secure token that was created by generate-token.

  This function decrypts the token, decodes the payload, parses it safely,
  and validates its expiration time.

  WARNING: This function depends on the `base64` and `openssl` command-line
  utilities being available in the system's PATH.

  #:returns: A parsed association list representing the token's payload if
             the token is valid and successfully decoded.
             Otherwise, it raises an error."

  ;; Ensure required arguments are provided.
  (unless token
    (error "decrypt-token: The 'token' was not found in the options list."))
  (unless encryption-key
    (error
     "decrypt-token: The 'encryption-key' was not found in the options list."))

  ;; Decrypt the token using OpenSSL.
  ;; The `-d` flag is for decryption. The `-a` flag expects base64 input.
  (let* ((decrypted-payload (syscall (format #f
                                      "echo '~a' | openssl aes-256-cbc -d -pbkdf2 -a -k '~a'"
                                      (string-ungarble token) encryption-key)))
         
         ;; Check if decryption produced any output. An empty string often
         ;; indicates a decryption failure (e.g., wrong key).
         (_ (if (string-null? decrypted-payload)
                (error
                 "decrypt-token: Decryption failed. Is the key or token correct?")))

         ;; Base64-decode the decrypted payload.
         (payload-string (syscall (format #f "echo '~a' | base64 --decode"
                                          decrypted-payload)))

         (payload (eval-string payload-string)))
    
    (let ((expiration-timestamp (assoc-ref payload
                                           'token-expires-at)))
      (unless (and expiration-timestamp
                   (number? expiration-timestamp))
        (error
         "decrypt-token: Token is invalid. Missing or malformed 'token-expires-at'"))

      (if (> (current-time) expiration-timestamp)
          (error "decrypt-token: Token has expired.") payload))))

(define* (decrypt-token #:key token encryption-key)
  (catch #t
         (lambda ()
           (unsafe-decrypt-token #:token token
                                 #:encryption-key encryption-key))
         (lambda (key . args)
           (display (format #f "error decrypting token: ~a: ~a" key args)) #f)))

(define* (generate-token #:key encryption-key
                         (get-owner-details (lambda ()
                                              '()))
                         (token-validity-seconds (* 72 3600)))
  (catch #t
         (lambda ()
           (unsafe-generate-token #:encryption-key encryption-key
                                  #:get-owner-details get-owner-details
                                  #:token-validity-seconds
                                  token-validity-seconds))
         (lambda (key . args)
           (display (format #f "Couldn't generate token: ~a: ~a" key args)) #f)))
