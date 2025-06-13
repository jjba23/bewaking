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
                           encrypt-payload
                           decrypt-payload
                           base16-encode
                           base16-decode
                           is-token-expired?
                           has-needed-permissions?
                           token-payload-valid?))

(define (syscall cmd)
  "Executes a shell command and captures its standard output.
  
   #:args
     cmd: A string representing the shell command to execute.
  
   #:returns
     A string containing the entire standard output of the executed command.
  
   #:example
     (syscall \"ls -l\") ; Returns a string with the directory listing"
  (let* ((process (open-input-pipe cmd))
         (process-output (get-string-all process)))
    (close-pipe process) process-output))

(define (string-garble s)
  "Garbles a string by splitting it into two halves, reversing each half,
   and then concatenating the reversed second half with the reversed first half.
   If the string has an odd length, the first half will be shorter by one character.
  
   #:args
     s: The input string to garble.
  
   #:return
     A new string that is the garbled version of the input string.
  
   Example:
   (string-garble \"abcdefg\") ; Returns \"gfedcba\"
   (string-garble \"hello world\")   ; Returns \"dlrow olleh\""
  (let* ((len (string-length s))
         (mid-point (floor (/ len 2)))
         (first-half-original (substring s 0 mid-point))
         (second-half-original (substring s mid-point len))
         (first-half-reversed (string-reverse first-half-original))
         (second-half-reversed (string-reverse second-half-original)))
    (string-append second-half-reversed first-half-reversed)))

(define (string-ungarble s)
  "Ungarbeles a string that was previously garbled by the `string-garble` function.
   It reconstructs the original string by reversing the process of `string-garble`.
  
   Args:
     s: The garbled string to ungarble.
  
   Returns:
     The original string before it was garbled.
  
   Example:
   (string-ungarble \"gfedcba\") ; Returns \"abcdefg\"
   (string-ungarble \"dlrow olleh\")   ; Returns \"hello world\""
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

(define (token-payload-valid? payload)
  "Verify the validity of a token payload, by doing checks
on every field, and returning either #t or #f representing validity status."
  (and (not (equal? #f
                    (assoc-ref payload
                               'token-type)))
       (not (equal? #f
                    (assoc-ref payload
                               'token-id)))
       (not (equal? #f
                    (assoc-ref payload
                               'token-created-at)))
       (not (equal? #f
                    (assoc-ref payload
                               'token-expires-at)))
       (not (equal? #f
                    (assoc-ref payload
                               'owner-id)))
       (not (equal? #f
                    (assoc-ref payload
                               'owner-name)))
       (not (equal? #f
                    (assoc-ref payload
                               'owner-permissions)))))

(define (encrypt-payload payload k)
  "Encrypts a given payload using AES256 encryption with a specified key.
  It leverages the `openssl` command-line tool.
  
   Args:
     payload: The string to encrypt.
     k: The encryption key (a string) to use.
  
   Returns:
     A string representing the base64-encoded, AES256-encrypted version of the payload.
  
   Example:
     (encrypt-payload \"mysecretdata\" \"mysecretkey\")
      Returns a string like \"U2FsdGVkX1+...\" "
  (syscall (format #f
                   "echo -n '~a' | openssl enc -aes256 -pbkdf2 -a -A -k '~a'"
                   payload k)))

(define (decrypt-payload payload k)
  "Decrypts an AES256-encrypted payload using a given key.
   It relies on the `openssl` command-line tool to perform the decryption.
  
   Args:
     payload: The base64-encoded, AES256-encrypted string to decrypt.
     k: The decryption key (a string) that was used to encrypt the payload.
  
   Returns:
     The original, decrypted data as a string.
  
   Example:
     (decrypt-payload \"U2FsdGVkX1+...\" \"mysecretkey\")
     Returns \"mysecretdata\" "
  (syscall (string-append "echo '" payload
            "' | openssl aes-256-cbc -d -pbkdf2 -a -A -base64 -k '" k "'")))

(define (base16-encode payload)
  (syscall (format #f "echo -n '~a' | xxd -plain | tr -d '\n'" payload)))

(define (base16-decode payload)
  (syscall (format #f "echo '~a' | xxd -plain -revert" payload)))

(define* (unsafe-generate-token #:key encryption-key signing-key
                                get-owner-details
                                (token-validity-seconds (* 7 24 3600)))
  "Generates a secure, encrypted, and Base64-encoded authentication token.

  #:key encryption-key:   The secret key (string) used for AES-256 encryption.
                           This parameter is required.
  #:key signing-key:      The signing key (string) used for the final AES-256 encryption.
                           This parameter is required.
  #:key get-owner-details: A thunk that returns an the owner's details.
  #:key token-validity-seconds: The token's lifetime in seconds.
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
         (_ (unless encryption-key
              (error
               "generate-token: The #:encryption-key keyword argument is required.")))
         (_ (unless owner-id
              (error
               "generate-token: Owner details from #:get-owner-details must contain an 'id'.")))

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
         (encrypted-payload (encrypt-payload base64-payload encryption-key))

         ;; Clean the final token by removing any trailing whitespace from the
         ;; openssl output, producing the final token.
         (token (string-trim-right encrypted-payload))
         (garbled-inner-token (string-garble token))

         (signed-token (string-trim-right (encrypt-payload garbled-inner-token
                                           signing-key))))
    
    (base16-encode (string-garble signed-token))))

(define* (unsafe-decrypt-token #:key token encryption-key signing-key)
  "Decodes and validates a secure token that was created by generate-token.

  This function decrypts the token, decodes the payload, parses it safely,
  and validates its expiration time.

  WARNING: This function depends on the `base64` and `openssl` command-line
  utilities being available in the system's PATH.

  #:returns: A parsed association list representing the token's payload if
             the token is valid and successfully decoded.
             Otherwise, it raises an error."

  (unless token
    (error "decrypt-token: The 'token' was not found."))
  (unless encryption-key
    (error "decrypt-token: The 'encryption-key' was not found."))
  (unless signing-key
    (error "decrypt-token: The 'signing-key' was not found."))

  ;; Decrypt the token using OpenSSL.
  ;; The `-d` flag is for decryption. The `-a` flag expects base64 input.
  (let* ((ddd (string-ungarble (base16-decode token)))
         (decrypted-signed-payload (decrypt-payload ddd signing-key))
         (decrypted-payload (decrypt-payload (string-ungarble
                                              decrypted-signed-payload)
                                             encryption-key))
         ;; Check if decryption produced any output. An empty string often
         ;; indicates a decryption failure (e.g., wrong key).
         (_ (if (string-null? decrypted-payload)
                (error
                 "decrypt-token: Decryption failed. Is the key or token correct?")))

         ;; Base64-decode the decrypted payload.
         (payload-string (syscall (format #f "echo '~a' | base64 --decode"
                                          decrypted-payload)))
         (payload (eval-string payload-string)))
    payload))

(define* (decrypt-token #:key token encryption-key signing-key)
  "Safely attempts to decrypt a given token.
   This function acts as a wrapper around `unsafe-decrypt-token`,
   catching any errors that occur during the decryption process.
  
   Args:
     token: The token string to be decrypted.
     encryption-key: The key used for encryption.
     signing-key: The key used for signing/verification.
  
   Returns:
     The decrypted token payload if successful, otherwise `#f`
     (false) and prints an error message to the console."
  (catch #t
         (lambda ()
           (unsafe-decrypt-token #:token token
                                 #:encryption-key encryption-key
                                 #:signing-key signing-key))
         (lambda (key . args)
           (display (format #f "error decrypting token: ~a: ~a" key args)) #f)))

(define* (generate-token #:key encryption-key signing-key get-owner-details
                         (token-validity-seconds (* 7 24 3600)))
  "Safely attempts to generate a new token.
   This function wraps `unsafe-generate-token` to gracefully handle
   any potential errors during token creation.
  
   Args:
     encryption-key: The key to be used for encrypting the token's payload.
     signing-key: The key to be used for signing the token.
     get-owner-details: A thunk that returns a list of details about the token's owner.
     token-validity-seconds: (Optional) The duration in seconds for which the token will be valid.
  
   Returns:
     A newly generated token string if successful, otherwise `#f`
     (false) and prints an error message to the console."
  (catch #t
         (lambda ()
           (unsafe-generate-token #:encryption-key encryption-key
                                  #:signing-key signing-key
                                  #:get-owner-details get-owner-details
                                  #:token-validity-seconds
                                  token-validity-seconds))
         (lambda (key . args)
           (display (format #f "Couldn't generate token: ~a: ~a" key args)) #f)))

(define* (has-needed-permissions? #:key needed present)
  "Check if needed permissions are a subset of the present (existing) permissions."
  (lset<= equal? needed present))

(define* (is-token-expired? #:key token)
      (let ((expiration-timestamp (assoc-ref token
                                           'token-expires-at)))
      (unless (and expiration-timestamp
                   (number? expiration-timestamp))
        (error
         "decrypt-token: Token is invalid. Missing or malformed 'token-expires-at'"))

      (> (current-time) expiration-timestamp)))
