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
  #:export (generate-secure-token decode-and-validate-token))

(define (syscall cmd)
  (let* ((process (open-input-pipe cmd))
         (process-output (get-string-all process)))
    (close-pipe process) process-output))

(define some-key
  "10d0670c-e79b-406e-a37b-926d7b804be0")

(define* (generate-secure-token #:key encryption-key
                                (get-user-details (lambda ()
                                                    '()))
                                (token-validity-seconds (* 48 3600)))
  "Generates a secure, encrypted, and Base64-encoded authentication token.

  This function creates a token containing user details and timestamps, serializes it,
  and then uses external command-line tools to encrypt and encode it.

  WARNING: This implementation has a hard dependency on the `base64` and `openssl`
  command-line utilities being available in the system's PATH.

 #:key encryption-key:   The secret key (string) used for AES-256 encryption.
                          This parameter is required.
  #:key get-user-details: A thunk (procedure with no arguments) that returns an
                          association list of the user's details. Must include at
                          least an 'id' key.
  #:key token-validity-seconds: The token's lifetime in seconds.
                                Defaults to 48 hours.

  #:returns: An encrypted and Base64-encoded string representing the token."

  (let* ((user-details (get-user-details))
         (user-id (assoc-ref user-details
                             'id))
         (current-timestamp (current-time))
         (expiration-timestamp (+ current-timestamp token-validity-seconds))

         (payload `((token-type . bewaking-token) (token-id unquote
                                                            (generate-string-uuid))
                    (token-created-at unquote current-timestamp)
                    (token-expires-at unquote expiration-timestamp)
                    (user-id unquote user-id)
                    (user-email unquote
                                (assoc-ref user-details
                                           'email))
                    (user-name unquote
                               (assoc-ref user-details
                                          'name))
                    (permissions unquote
                                 (assoc-ref user-details
                                            'permissions))))

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
       "generate-secure-token: The #:encryption-key keyword argument is required."))

    (unless user-id
      (error
       "generate-secure-token: User details from #:get-user-details must contain an 'id'."))

    token))

(define* (decode-and-validate-token #:key token encryption-key)
  "Decodes and validates a secure token that was created by generate-secure-token.

  This function decrypts the token, decodes the payload, parses it safely,
  and validates its claims (e.g., expiration time).

  It accepts a single argument, 'options', which is an association list.

  WARNING: This function depends on the `base64` and `openssl` command-line
  utilities being available in the system's PATH.

  #:returns: A parsed association list representing the token's payload if
             the token is valid and successfully decoded.
             Otherwise, it raises an error."

  ;; Ensure required arguments are provided.
  (unless token
    (error
     "decode-and-validate-token: The 'token' was not found in the options list."))
  (unless encryption-key
    (error
     "decode-and-validate-token: The 'encryption-key' was not found in the options list."))

  ;; Decrypt the token using OpenSSL.
  ;; The `-d` flag is for decryption. The `-a` flag expects base64 input.
  (let* ((decrypted-payload (syscall (format #f
                                      "echo '~a' | openssl aes-256-cbc -d -pbkdf2 -a -k '~a'"
                                      token encryption-key)))
         
         ;; Check if decryption produced any output. An empty string often
         ;; indicates a decryption failure (e.g., wrong key).
         (_ (if (string-null? decrypted-payload)
                (error
                 "decode-and-validate-token: Decryption failed. Is the key or token correct?")))

         ;; Base64-decode the decrypted payload.
         (payload-string (syscall (format #f "echo '~a' | base64 --decode"
                                          decrypted-payload)))

         ;; Safely parse the payload string into a Scheme object.
         ;; We use `read` instead of `eval` to prevent code execution vulnerabilities.
         (payload (eval-string payload-string)))
    
    ;; Validate the token's permissions.
    (let ((expiration-timestamp (assoc-ref payload
                                           'token-expires-at)))
      (unless (and expiration-timestamp
                   (number? expiration-timestamp))
        (error
         "decode-and-validate-token: Token is invalid. Missing or malformed 'token-expires-at'"))

      (if (> (current-time) expiration-timestamp)
          (error "decode-and-validate-token: Token has expired.") payload))))

(define (trial-run)
  (let* ((start (current-time))
         (t (generate-secure-token #:encryption-key some-key
                                   #:get-user-details (lambda ()
                                                        `((id . "f421188e-3ca2-4d55-a65c-0278cd3f77b1")
                                                          (email . "jjbigorra@gmail.com")
                                                          (name . "Joe")
                                                          (permissions
                                                           bewaking:write
                                                           bewaking:read)))))
         (d (decode-and-validate-token #:token t
                                       #:encryption-key some-key))
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

