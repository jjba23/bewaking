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
  #:use-module (ice-9 format)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-11)
  #:use-module (bewaking crypto)
  ;; Base16 encoding and decoding are implemented in (bewaking crypto) and
  ;; re-exported here so that bewaking's public API is unchanged.
  #:re-export (base16-encode base16-decode)
  #:export (generate-token decrypt-token
                           unsafe-generate-token
                           string-garble
                           string-ungarble
                           unsafe-decrypt-token
                           encrypt-payload
                           decrypt-payload
                           encrypt-object
                           decrypt-object
                           unsafe-encrypt-object
                           unsafe-decrypt-object
                           seal-envelope
                           open-envelope
                           sealed-envelope?
                           envelope-metadata
                           envelope-expired?
                           seal-format-version
                           default-key-id
                           is-token-expired?
                           token-remaining-seconds
                           token-valid?
                           has-needed-permissions?
                           token-payload-valid?))

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

(define (serialize-payload payload)
  "Serialize any Scheme datum into a portable, human-readable string using `write`.
   The result is guaranteed to be readable back with `read`, and keeps the exact
   structure of the original datum (lists, alists, vectors, numbers, strings...)."
  (with-output-to-string (lambda () (write payload))))

(define (deserialize-payload payload-string)
  "Safely read a Scheme datum back from a string produced by `serialize-payload`.
   Reading data (as opposed to evaluating it) is intentional: unlike `eval-string`,
   `read` cannot execute arbitrary code. Guile disables the `#.` read-eval syntax
   by default, so untrusted decrypted content is treated strictly as data."
  (with-input-from-string payload-string read))

(define (encrypt-payload payload k)
  "Encrypt @var{payload} with AES-256-CBC under the passphrase @var{k}.

   The output uses exactly the layout of
   @code{openssl enc -aes256 -pbkdf2 -a -A -k KEY}, so data produced by either
   implementation can be read by the other:

   - an 8-byte random salt, stored in an OpenSSL @code{Salted__} header;
   - a 32-byte key and a 16-byte IV derived from the passphrase and that salt
     with PBKDF2-HMAC-SHA256 over 10000 iterations;
   - AES-256-CBC with PKCS#7 padding, Base64-encoded on a single line.

   The work happens inside this process; nothing is passed to a shell.

   #:args
     payload: The string to encrypt.
     k: The encryption key (a string) to use.

   #:returns
     A Base64 string such as \"U2FsdGVkX1+...\".

   #:example
     (encrypt-payload \"mysecretdata\" \"mysecretkey\")"
  (openssl-encrypt payload k))

(define (decrypt-payload payload k)
  "Decrypt a payload previously produced by `encrypt-payload`, by
   @code{openssl enc -aes256 -pbkdf2 -a -A}, or by any other implementation of
   that format. Raises an error when the input is not in that format or when
   its padding is invalid, which is how a wrong key is reported.

   #:args
     payload: The Base64-encoded, AES256-encrypted string to decrypt.
     k: The decryption key (a string) that was used to encrypt the payload.

   #:returns
     The original, decrypted data as a string.

   #:example
     (decrypt-payload \"U2FsdGVkX1+...\" \"mysecretkey\")"
  (openssl-decrypt payload k))

(define (seal-string plaintext encryption-key signing-key)
  "Apply bewaking's layered sealing pipeline to a plaintext string.

   The pipeline is: AES-256 encrypt (encryption-key) -> garble -> AES-256
   encrypt (signing-key) -> garble -> base16 encode. The result is a portable
   hexadecimal string that can only be reopened with both keys.

   This is the shared core used by `unsafe-generate-token`, `unsafe-encrypt-object`
   and their safe wrappers."
  (let* ((encrypted-inner (string-trim-right (encrypt-payload plaintext
                                                             encryption-key)))
         (garbled-inner (string-garble encrypted-inner))
         (signed-token (string-trim-right (encrypt-payload garbled-inner
                                                           signing-key))))
    (base16-encode (string-garble signed-token))))

(define (unseal-string sealed encryption-key signing-key)
  "Reverse `seal-string`, returning the original plaintext string.

   The steps are inverted in order: base16 decode -> ungarble -> AES-256
   decrypt (signing-key) -> ungarble -> AES-256 decrypt (encryption-key)."
  (let* ((ddd (string-ungarble (base16-decode sealed)))
         (decrypted-signed-payload (decrypt-payload ddd signing-key))
         (decrypted-payload (decrypt-payload (string-ungarble
                                              decrypted-signed-payload)
                                             encryption-key)))
    decrypted-payload))

;; ====== Versioned, authenticated envelope ======
;;
;; Sealed tokens and objects use a self-describing, integrity-protected envelope
;; whose header carries rotation metadata:
;;
;;     BWK2.<key-id>.<created-at>.<expires-at>.<body>.<mac>
;;
;; where
;;   - <key-id>     identifies which key sealed the data (key rotation),
;;   - <created-at> is the Unix timestamp (seconds) at sealing time,
;;   - <expires-at> is the Unix timestamp after which the data must not be
;;                  opened, or "-" when it never expires,
;;   - <body>       is the Base16 string produced by `seal-string`,
;;   - <mac>        is the hexadecimal HMAC-SHA256 of the whole header and body
;;                  ("BWK2.<key-id>.<created-at>.<expires-at>.<body>").
;;
;; The metadata is authenticated by the MAC, so it can be trusted once verified
;; and can be inspected *without* any key for auditing (`envelope-metadata`,
;; `envelope-expired?`). The version tag lets the format evolve, and only the
;; current version is understood: an older envelope, a pre-versioning bare Base16
;; token, or arbitrary text is refused.

(define seal-format-version
  "BWK2")

(define no-expiry-marker
  "-")

(define default-key-id
  "default")

(define (derive-mac-key signing-key)
  "Derive the default HMAC key from the signing key.

   A fixed domain-separation suffix is appended so that the MAC key differs
   from the AES key even when the caller only supplies a signing key."
  (string-append signing-key "|bewaking-mac-v1"))

(define (valid-key-id? key-id)
  "Return #t when @var{key-id} is a non-empty label without dots or whitespace,
   so that it can be embedded in the dot-separated envelope header."
  (and (string? key-id)
       (> (string-length key-id) 0)
       (not (string-contains key-id "."))
       (not (string-any char-set:whitespace key-id))))

(define (compute-mac message mac-key)
  "Compute HMAC-SHA256 of @var{message}, keyed by @var{mac-key}, and return it as
   a lowercase hexadecimal string. The MAC is computed in this process with
   libgcrypt; no external program is run."
  (hmac-sha256-hex mac-key message))

(define (constant-time-string=? a b)
  "Compare two strings for equality without an early exit, to avoid leaking the
   position of the first differing byte through timing."
  (let ((length-a (string-length a)))
    (if (not (= length-a (string-length b)))
        #f
        (let loop ((i 0) (difference 0))
          (if (= i length-a)
              (= difference 0)
              (loop (+ i 1)
                    (logior difference
                            (logxor (char->integer (string-ref a i))
                                    (char->integer (string-ref b i))))))))))

(define (sealed-envelope? sealed)
  "Return #t when @var{sealed} is a versioned, authenticated bewaking envelope
   of the current format version."
  (and (string? sealed)
       (string-prefix? (string-append seal-format-version ".") sealed)))

(define (parse-envelope sealed)
  "Parse an envelope into an alist with @code{version}, @code{key-id},
   @code{created-at}, @code{expires-at}, @code{body} and @code{mac}. Raises an
   error when the structure is malformed."
  (let ((parts (string-split sealed #\.)))
    (unless (= (length parts) 6)
      (error
       (format #f "bewaking: malformed ~a envelope" seal-format-version)))
    (let ((created-at (string->number (list-ref parts 2)))
          (expires-raw (list-ref parts 3)))
      (unless (integer? created-at)
        (error
         (format #f "bewaking: malformed ~a envelope (created-at)"
                 seal-format-version)))
      (list (cons 'version seal-format-version)
            (cons 'key-id (list-ref parts 1))
            (cons 'created-at created-at)
            (cons 'expires-at
                  (if (string=? expires-raw no-expiry-marker)
                      #f
                      (let ((expires (string->number expires-raw)))
                        (unless (integer? expires)
                          (error
                           (format #f
                                   "bewaking: malformed ~a envelope (expires-at)"
                                   seal-format-version)))
                        expires)))
            (cons 'body (list-ref parts 4))
            (cons 'mac (list-ref parts 5))))))

(define (envelope-mac-message info)
  "Build the exact string authenticated by the MAC, from a parsed envelope alist
   as returned by `parse-envelope`."
  (let ((version (assoc-ref info 'version))
        (key-id (assoc-ref info 'key-id))
        (created-at (assoc-ref info 'created-at))
        (expires-at (assoc-ref info 'expires-at))
        (body (assoc-ref info 'body)))
    (format #f "~a.~a.~a.~a.~a" version key-id created-at
            (or expires-at no-expiry-marker) body)))

(define* (envelope-metadata #:key sealed)
  "Return an alist of envelope metadata without needing any key:
   @code{version}, @code{key-id}, @code{created-at} and @code{expires-at}.

   @code{expires-at} is #f when the data never expires. Returns #f when
   @var{sealed} is not a current-version envelope. The metadata is covered by
   the MAC, so it can be audited safely."
  (unless sealed
    (error "envelope-metadata: The 'sealed' was not found."))
  (if (sealed-envelope? sealed)
      (let ((info (parse-envelope sealed)))
        (list (cons 'version (assoc-ref info 'version))
              (cons 'key-id (assoc-ref info 'key-id))
              (cons 'created-at (assoc-ref info 'created-at))
              (cons 'expires-at (assoc-ref info 'expires-at))))
      #f))

(define* (envelope-expired? #:key sealed (now (current-time)))
  "Return #t when @var{sealed} is an envelope carrying an @code{expires-at} in the
   past relative to @var{now}, and #f otherwise — including envelopes with no
   expiry and non-envelope values.

   This is an unauthenticated audit helper that reads the header only. Use
   `open-envelope`, which verifies the MAC, to enforce expiry during decryption."
  (let ((metadata (envelope-metadata #:sealed sealed)))
    (if metadata
        (let ((expires-at (assoc-ref metadata 'expires-at)))
          (and expires-at (> now expires-at)))
        #f)))

(define* (key-material #:key keyring key-id encryption-key signing-key mac-key
                       (now (current-time)))
  "Resolve the encryption, signing and MAC keys to use.

   When @var{keyring} is supplied it takes precedence: it must be an alist
   mapping a key id to an entry alist with `encryption-key`, `signing-key`,
   (optional) `mac-key`, and optional `not-before` / `not-after` timestamps
   describing the window during which the key may be used. Using a key outside
   its window raises an error, which is how rotation policies are enforced.
   Otherwise the explicit keys are used. The MAC key defaults to
   `derive-mac-key` of the signing key. Returns three values: encryption key,
   signing key, MAC key."
  (if keyring
      (let ((entry (assoc key-id keyring)))
        (unless entry
          (error
           (format #f "bewaking: no keyring entry for key id '~a'" key-id)))
        (let* ((entry-alist (cdr entry))
               (not-before (assoc-ref entry-alist 'not-before))
               (not-after (assoc-ref entry-alist 'not-after))
               (entry-signing-key (assoc-ref entry-alist 'signing-key)))
          (when (and not-before (> not-before now))
            (error
             (format #f "bewaking: the key '~a' is not valid yet." key-id)))
          (when (and not-after (> now not-after))
            (error
             (format #f "bewaking: the key '~a' has been retired." key-id)))
          (values (assoc-ref entry-alist 'encryption-key)
                  entry-signing-key
                  (or (assoc-ref entry-alist 'mac-key)
                      (and entry-signing-key
                           (derive-mac-key entry-signing-key))))))
      (values encryption-key signing-key
              (or mac-key
                  (and signing-key (derive-mac-key signing-key))))))

(define* (seal-envelope #:key plaintext encryption-key signing-key
                        (key-id default-key-id) mac-key
                        (created-at (current-time)) expires-at ttl-seconds)
  "Seal a plaintext string into a versioned, authenticated envelope.

   The output is
   @code{BWK2.<key-id>.<created-at>.<expires-at>.<body>.<mac>}. Both an
   encryption key and a signing key are required. The MAC key may be supplied
   explicitly, or is derived from the signing key.

   #:key created-at:  Unix timestamp to record (default: now).
   #:key expires-at:  Unix timestamp after which the data must not be opened.
   #:key ttl-seconds: convenience; sets expires-at to created-at + ttl-seconds.
                      Give at most one of expires-at / ttl-seconds.

   #:example
     (seal-envelope #:plaintext some-plaintext #:encryption-key k1
                    #:signing-key k2 #:ttl-seconds (* 24 3600))"
  (unless (string? plaintext)
    (error "seal-envelope: The 'plaintext' must be a string."))
  (unless encryption-key
    (error "seal-envelope: The 'encryption-key' was not found."))
  (unless signing-key
    (error "seal-envelope: The 'signing-key' was not found."))
  (unless (valid-key-id? key-id)
    (error
     "seal-envelope: The 'key-id' must be a non-empty label without dots or whitespace."))
  (when (and expires-at ttl-seconds)
    (error
     "seal-envelope: give either 'expires-at' or 'ttl-seconds', not both."))
  (unless (integer? created-at)
    (error "seal-envelope: The 'created-at' must be an integer timestamp."))
  (when (and expires-at (not (integer? expires-at)))
    (error "seal-envelope: The 'expires-at' must be an integer timestamp."))
  (when (and ttl-seconds (not (integer? ttl-seconds)))
    (error "seal-envelope: The 'ttl-seconds' must be an integer number of seconds."))
  (let* ((effective-mac-key (or mac-key (derive-mac-key signing-key)))
         (effective-expires (cond (expires-at expires-at)
                                  (ttl-seconds (+ created-at ttl-seconds))
                                  (else #f)))
         (body (seal-string plaintext encryption-key signing-key))
         (info (list (cons 'version seal-format-version)
                     (cons 'key-id key-id)
                     (cons 'created-at created-at)
                     (cons 'expires-at effective-expires)
                     (cons 'body body)))
         (mac (compute-mac (envelope-mac-message info) effective-mac-key)))
    (format #f "~a.~a.~a.~a.~a.~a" seal-format-version key-id created-at
            (or effective-expires no-expiry-marker) body mac)))

(define* (open-envelope #:key sealed encryption-key signing-key mac-key keyring
                        (enforce-expiry? #t) (now (current-time))
                        max-age-seconds)
  "Open a sealed envelope and return its plaintext string.

   Envelopes are integrity-checked with their MAC *before* any decryption is
   attempted, so tampering is reported explicitly. The MAC also covers the
   rotation metadata (key id, created-at, expires-at).

   #:key enforce-expiry?: when #t (the default) an envelope whose
                         @code{expires-at} is in the past is rejected.
   #:key now:             current Unix timestamp, for deterministic checks.
   #:key max-age-seconds: optional; reject envelopes created longer ago than this.
   #:key keyring:         optional alist of key id to key entry; the entry's
                         @code{not-before} / @code{not-after} window is enforced.

   Anything that is not an envelope of the current format version — an older
   envelope, a pre-versioning bare Base16 token, or arbitrary text — is refused."
  (unless sealed
    (error "open-envelope: The 'sealed' was not found."))
  (unless (sealed-envelope? sealed)
    (error (format #f "open-envelope: not a ~a envelope." seal-format-version)))
  (let* ((info (parse-envelope sealed))
         (key-id (assoc-ref info 'key-id))
         (created-at (assoc-ref info 'created-at))
         (expires-at (assoc-ref info 'expires-at))
         (body (assoc-ref info 'body))
         (stored-mac (assoc-ref info 'mac)))
        (let-values (((effective-encryption-key effective-signing-key
                       effective-mac-key)
                      (key-material #:keyring keyring #:key-id key-id
                                    #:encryption-key encryption-key
                                    #:signing-key signing-key
                                    #:mac-key mac-key
                                    #:now now)))
          (unless effective-encryption-key
            (error "open-envelope: no encryption key for this envelope."))
          (unless effective-signing-key
            (error "open-envelope: no signing key for this envelope."))
          (let ((expected-mac (compute-mac (envelope-mac-message info)
                                           effective-mac-key)))
            (unless (constant-time-string=? expected-mac stored-mac)
              (error
               "open-envelope: integrity check failed. The sealed data was tampered with or the wrong key was used.")))
          (when (and enforce-expiry? expires-at (> now expires-at))
            (error
             (format #f
                     "open-envelope: the sealed data expired at ~a (key '~a')."
                     expires-at key-id)))
          (when (and max-age-seconds created-at
                     (> (- now created-at) max-age-seconds))
            (error
             (format #f
                     "open-envelope: the sealed data was created at ~a, older than the allowed maximum age of ~a seconds."
                     created-at max-age-seconds)))
          (unseal-string body effective-encryption-key effective-signing-key))))

(define* (unsafe-generate-token #:key encryption-key signing-key keyring
                                (key-id default-key-id) mac-key
                                get-owner-details
                                (token-validity-seconds (* 7 24 3600))
                                ttl-seconds expires-at)
  "Generates a secure, versioned, authenticated token.

  #:key encryption-key:   The secret key (string) used for AES-256 encryption.
  #:key signing-key:      The signing key (string) used for the outer AES-256
                          encryption and for the HMAC.
  #:key keyring:          Optional alist of key-id -> key entry used to select
                          keys instead of the explicit keys above.
  #:key key-id:           Key identifier embedded in the envelope (default
                          \"default\"). Enables key rotation.
  #:key mac-key:          Optional explicit HMAC key; defaults to a key derived
                          from the signing key.
  #:key get-owner-details: A thunk that returns an the owner's details.
  #:key token-validity-seconds: The token's payload lifetime in seconds.
  #:key ttl-seconds:      Optional envelope lifetime in seconds. When given, the
                          sealed envelope records an expiry and `decrypt-token`
                          refuses to open it afterwards (default: no expiry).
  #:key expires-at:       Optional Unix timestamp for the envelope expiry;
                          mutually exclusive with ttl-seconds.
  #:returns: A versioned, authenticated token string."

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
         (_ (unless owner-id
              (error
               "generate-token: Owner details from #:get-owner-details must contain an 'id'.")))

         ;; Serialize the payload and Base64-encode it for safe transport.
         (base64-payload (base64-encode (serialize-payload payload))))

    ;; Resolve the keys (explicit or from the keyring) and seal the payload
    ;; into a versioned, authenticated envelope.
    (let-values (((effective-encryption-key effective-signing-key effective-mac-key)
                  (key-material #:keyring keyring #:key-id key-id
                                #:encryption-key encryption-key
                                #:signing-key signing-key
                                #:mac-key mac-key)))
      (unless effective-encryption-key
        (error
         "generate-token: The #:encryption-key keyword argument is required."))
      (unless effective-signing-key
        (error
         "generate-token: The #:signing-key keyword argument is required."))
      (seal-envelope #:plaintext base64-payload
                     #:encryption-key effective-encryption-key
                     #:signing-key effective-signing-key
                     #:key-id key-id #:mac-key effective-mac-key
                     #:ttl-seconds ttl-seconds #:expires-at expires-at))))

(define* (unsafe-decrypt-token #:key token encryption-key signing-key
                               mac-key keyring
                               (enforce-expiry? #t) max-age-seconds
                               (now (current-time)))
  "Decodes and validates a secure token created by `generate-token`.

  Tokens carry a version tag, a key id and an integrity MAC. The MAC is checked
  *before* decryption, so tampering is reported explicitly. Anything that is not
  a current-version envelope is refused.

  All cryptography is performed in this process (see the module
  `(bewaking crypto)`); no external command-line tools are involved.

  #:key token:          The token string to decrypt.
  #:key encryption-key: The key used for the inner AES-256 encryption.
  #:key signing-key:    The key used for the outer AES-256 encryption and MAC.
  #:key mac-key:        Optional explicit HMAC key; defaults to a key derived
                        from the signing key.
  #:key keyring:        Optional alist of key-id -> key entry. When supplied,
                        keys are selected using the token's own key id.
  #:key enforce-expiry?: When #t (the default), an envelope whose expiry has
                        passed is rejected.
  #:key max-age-seconds: Optional rotation policy; reject envelopes sealed
                        longer ago than this.
  #:key now:            Current Unix timestamp, for deterministic checks.

  #:returns: A parsed association list representing the token's payload if
             the token is valid and successfully decoded.
             Otherwise, it raises an error."

  (unless token
    (error "decrypt-token: The 'token' was not found."))
  (unless (or keyring encryption-key)
    (error "decrypt-token: The 'encryption-key' was not found."))
  (unless (or keyring signing-key)
    (error "decrypt-token: The 'signing-key' was not found."))

  (let* ((decrypted-payload (open-envelope #:sealed token
                                           #:encryption-key encryption-key
                                           #:signing-key signing-key
                                           #:mac-key mac-key
                                           #:keyring keyring
                                           #:enforce-expiry? enforce-expiry?
                                           #:max-age-seconds max-age-seconds
                                           #:now now))
         ;; Check if decryption produced any output. An empty string often
         ;; indicates a decryption failure (e.g., wrong key).
         (_ (if (string-null? decrypted-payload)
                (error
                 "decrypt-token: Decryption failed. Is the key or token correct?")))
         ;; Base64-decode the decrypted payload and read it back as data.
         (payload-string (base64-decode decrypted-payload))
         (_ (if (string-null? payload-string)
                (error
                 "decrypt-token: Decryption failed. Is the key or token correct?")))
         (payload (deserialize-payload payload-string)))
    payload))

(define* (decrypt-token #:key token encryption-key signing-key mac-key keyring
                        (enforce-expiry? #t) max-age-seconds)
  "Safely attempts to decrypt a given token.
   This function acts as a wrapper around `unsafe-decrypt-token`,
   catching any errors that occur during the decryption process.

   Args:
     token: The token string to be decrypted.
     encryption-key: The key used for encryption.
     signing-key: The key used for signing/verification.
     mac-key: (Optional) The HMAC key; defaults to a value derived from the signing key.
     keyring: (Optional) alist of key-id -> key entry for key rotation.
     enforce-expiry?: (Optional) when #t (the default) expired envelopes are rejected.
     max-age-seconds: (Optional) reject envelopes sealed longer ago than this.

   Returns:
     The decrypted token payload if successful, otherwise `#f`
     (false) and prints an error message to the console."
  (catch #t
         (lambda ()
           (unsafe-decrypt-token #:token token
                                 #:encryption-key encryption-key
                                 #:signing-key signing-key
                                 #:mac-key mac-key
                                 #:keyring keyring
                                 #:enforce-expiry? enforce-expiry?
                                 #:max-age-seconds max-age-seconds))
         (lambda (key . args)
           (display (format #f "error decrypting token: ~a: ~a" key args)) #f)))

(define* (generate-token #:key encryption-key signing-key keyring (key-id default-key-id)
                         mac-key get-owner-details
                         (token-validity-seconds (* 7 24 3600))
                         ttl-seconds expires-at)
  "Safely attempts to generate a new token.
   This function wraps `unsafe-generate-token` to gracefully handle
   any potential errors during token creation.

   Args:
     encryption-key: The key to be used for encrypting the token's payload.
     signing-key: The key to be used for signing the token.
     keyring: (Optional) alist of key-id -> key entry for key rotation.
     key-id: (Optional) label embedded in the envelope (default \"default\").
     mac-key: (Optional) The HMAC key; defaults to a value derived from the signing key.
     get-owner-details: A thunk that returns a list of details about the token's owner.
     token-validity-seconds: (Optional) The payload validity duration in seconds.
     ttl-seconds: (Optional) Envelope lifetime in seconds; seals an expiry into the token.
     expires-at: (Optional) Explicit Unix timestamp for the envelope expiry.

   Returns:
     A newly generated token string if successful, otherwise `#f`
     (false) and prints an error message to the console."
  (catch #t
         (lambda ()
           (unsafe-generate-token #:encryption-key encryption-key
                                  #:signing-key signing-key
                                  #:keyring keyring
                                  #:key-id key-id
                                  #:mac-key mac-key
                                  #:get-owner-details get-owner-details
                                  #:token-validity-seconds
                                  token-validity-seconds
                                  #:ttl-seconds ttl-seconds
                                  #:expires-at expires-at))
         (lambda (key . args)
           (display (format #f "Couldn't generate token: ~a: ~a" key args)) #f)))

(define* (unsafe-encrypt-object #:key payload encryption-key signing-key
                                keyring (key-id default-key-id) mac-key
                                ttl-seconds expires-at)
  "Seal an arbitrary Scheme datum (not just a token payload) into a portable,
   versioned, authenticated string. Any value that `write` can serialize is
   supported: alists, lists, vectors, numbers, strings, booleans, etc.

   #:key payload: The Scheme datum to protect.
   #:key encryption-key: The inner AES-256 key (string). Required unless a
                         keyring is supplied.
   #:key signing-key: The outer AES-256 key (string), also keying the HMAC.
   #:key keyring: Optional alist of key-id -> key entry for key rotation.
   #:key key-id: Key identifier embedded in the envelope (default \"default\").
   #:key mac-key: Optional explicit HMAC key; defaults to a key derived from
                 the signing key.
   #:key ttl-seconds: Optional envelope lifetime in seconds. The envelope then
                 records an expiry and refuses to reopen afterwards.
   #:key expires-at: Optional Unix timestamp for the envelope expiry; mutually
                 exclusive with ttl-seconds.
   #:returns: A versioned, authenticated envelope string.

   #:example
     (unsafe-encrypt-object #:payload '((user . \"joe\") (role . admin))
                            #:encryption-key \"...\" #:signing-key \"...\")"
  (unless payload
    (error "encrypt-object: The 'payload' was not found."))
  (unless (or keyring encryption-key)
    (error "encrypt-object: The 'encryption-key' was not found."))
  (unless (or keyring signing-key)
    (error "encrypt-object: The 'signing-key' was not found."))
  (let-values (((effective-encryption-key effective-signing-key effective-mac-key)
                (key-material #:keyring keyring #:key-id key-id
                              #:encryption-key encryption-key
                              #:signing-key signing-key
                              #:mac-key mac-key)))
    (unless effective-encryption-key
      (error "encrypt-object: The 'encryption-key' was not found."))
    (unless effective-signing-key
      (error "encrypt-object: The 'signing-key' was not found."))
    (seal-envelope #:plaintext (base64-encode (serialize-payload payload))
                   #:encryption-key effective-encryption-key
                   #:signing-key effective-signing-key
                   #:key-id key-id #:mac-key effective-mac-key
                   #:ttl-seconds ttl-seconds #:expires-at expires-at)))

(define* (encrypt-object #:key payload encryption-key signing-key
                         keyring (key-id default-key-id) mac-key
                         ttl-seconds expires-at)
  "Safely seal an arbitrary Scheme datum. Wraps `unsafe-encrypt-object`,
   catching errors and returning #f instead of raising.

   See `unsafe-encrypt-object` for the keyword arguments."
  (catch #t
         (lambda ()
           (unsafe-encrypt-object #:payload payload
                                  #:encryption-key encryption-key
                                  #:signing-key signing-key
                                  #:keyring keyring
                                  #:key-id key-id
                                  #:mac-key mac-key
                                  #:ttl-seconds ttl-seconds
                                  #:expires-at expires-at))
         (lambda (key . args)
           (display (format #f "Couldn't encrypt object: ~a: ~a" key args)) #f)))

(define* (unsafe-decrypt-object #:key object encryption-key signing-key
                                mac-key keyring
                                (enforce-expiry? #t) max-age-seconds
                                (now (current-time)))
  "Reopen a string produced by `unsafe-encrypt-object`, returning the original
   Scheme datum. Envelopes are integrity-checked with their MAC before any
   decryption, so tampering is reported explicitly. Raises an error if the
   object cannot be decrypted.

   #:key object: The sealed string to decrypt.
   #:key encryption-key: The inner AES-256 key (string).
   #:key signing-key: The outer AES-256 key (string).
   #:key mac-key: Optional explicit HMAC key; defaults to a key derived from
                 the signing key.
   #:key keyring: Optional alist of key-id -> key entry. When supplied, keys
                 are selected using the sealed data's own key id.
   #:key enforce-expiry?: When #t (the default), an object whose envelope expiry
                 has passed is rejected.
   #:key max-age-seconds: Optional rotation policy; reject objects sealed longer
                 ago than this.
   #:key now: Current Unix timestamp, for deterministic checks.
   #:returns: The original Scheme datum."
  (unless object
    (error "decrypt-object: The 'object' was not found."))
  (unless (or keyring encryption-key)
    (error "decrypt-object: The 'encryption-key' was not found."))
  (unless (or keyring signing-key)
    (error "decrypt-object: The 'signing-key' was not found."))
  (let* ((decrypted-payload (open-envelope #:sealed object
                                           #:encryption-key encryption-key
                                           #:signing-key signing-key
                                           #:mac-key mac-key
                                           #:keyring keyring
                                           #:enforce-expiry? enforce-expiry?
                                           #:max-age-seconds max-age-seconds
                                           #:now now))
         (_ (if (string-null? decrypted-payload)
                (error
                 "decrypt-object: Decryption failed. Is the key or object correct?")))
         (payload-string (base64-decode decrypted-payload))
         (_ (if (string-null? payload-string)
                (error
                 "decrypt-object: Decryption failed. Is the key or object correct?")))
         (payload (deserialize-payload payload-string)))
    (if (eof-object? payload)
        (error "decrypt-object: Decrypted content was not a readable Scheme datum.")
        payload)))

(define* (decrypt-object #:key object encryption-key signing-key
                         mac-key keyring
                         (enforce-expiry? #t) max-age-seconds)
  "Safely reopen a string produced by `encrypt-object`. Wraps
   `unsafe-decrypt-object`, catching errors and returning #f instead of raising.

   See `unsafe-decrypt-object` for the keyword arguments."
  (catch #t
         (lambda ()
           (unsafe-decrypt-object #:object object
                                  #:encryption-key encryption-key
                                  #:signing-key signing-key
                                  #:mac-key mac-key
                                  #:keyring keyring
                                  #:enforce-expiry? enforce-expiry?
                                  #:max-age-seconds max-age-seconds))
         (lambda (key . args)
           (display (format #f "error decrypting object: ~a: ~a" key args)) #f)))

(define* (has-needed-permissions? #:key needed present)
  "Check if needed permissions are a subset of the present (existing) permissions."
  (lset<= equal? needed present))

(define* (token-remaining-seconds #:key token)
  "Return the number of seconds left before the token expires.

   The value is positive while the token is still valid, zero at the exact
   expiry instant, and negative once the token has expired. Raises an error
   when @code{token-expires-at} is missing or is not a number.

   #:key token: A decrypted token payload (association list)."
  (let ((expiration-timestamp (assoc-ref token
                                         'token-expires-at)))
    (unless (and expiration-timestamp
                 (number? expiration-timestamp))
      (error
       "token-remaining-seconds: Token is invalid. Missing or malformed 'token-expires-at'"))
    (- expiration-timestamp (current-time))))

(define* (is-token-expired? #:key token)
  "Return #t when the token's @code{token-expires-at} timestamp is in the past,
   and #f while the token is still valid. Raises an error when the payload is
   missing a well-formed @code{token-expires-at} field.

   #:key token: A decrypted token payload (association list).

   #:example
     (is-token-expired? #:token (decrypt-token #:token t
                                               #:encryption-key k1
                                               #:signing-key k2))"
  (let ((expiration-timestamp (assoc-ref token
                                         'token-expires-at)))
    (unless (and expiration-timestamp
                 (number? expiration-timestamp))
      (error
       "is-token-expired?: Token is invalid. Missing or malformed 'token-expires-at'"))

    (> (current-time) expiration-timestamp)))

(define* (token-valid? #:key token)
  "Return #t when the decrypted token payload is structurally valid
   (`token-payload-valid?`) and has not expired yet (`is-token-expired?`).

   #:key token: A decrypted token payload (association list)."
  (and (token-payload-valid? token)
       (not (is-token-expired? #:token token))))
