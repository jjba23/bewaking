;; bewaking
;;
;; SPDX-License-Identifier: MIT
;; Copyright © Josep Bigorra <jjbigorra@gmail.com>

(define-module (bewaking bewaking)
  #:use-module (uuid generate)
  #:use-module (ice-9 format)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-11)
  #:use-module (rnrs bytevectors)
  #:use-module (bewaking crypto)
  ;; Base16 encoding and decoding are implemented in (bewaking crypto) and
  ;; re-exported here so that bewaking's public API is unchanged. The KDF
  ;; defaults and the Argon2 availability check come from there too, so callers
  ;; can pick a key-derivation function without importing a second module.
  #:re-export (base16-encode base16-decode
                default-kdf argon2id-available?)
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
                           readable-seal-format-versions
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

(define* (encrypt-payload payload k #:key (kdf default-kdf))
  "Encrypt @var{payload} with AES-256-CBC under the passphrase @var{k}, deriving
   the AES key and IV with @var{kdf} (see @code{kdf-spec} in
   @code{(bewaking crypto)}). The result records which derivation was used, so
   it can always be opened again without being told.

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

   #:key kdf: the key-derivation specification; @code{'pbkdf2} (the default)
              keeps the OpenSSL-compatible layout, @code{'argon2id} selects
              Argon2id with its default parameters.

   #:example
     (encrypt-payload \"mysecretdata\" \"mysecretkey\")
     (encrypt-payload \"mysecretdata\" \"mysecretkey\" #:kdf 'argon2id)"
  (kdf-encrypt payload k #:kdf kdf))

(define (decrypt-payload payload k)
  "Decrypt a payload previously produced by `encrypt-payload`, by
   @code{openssl enc -aes256 -pbkdf2 -a -A}, or by any other implementation of
   that format. Which key derivation to use is read from the payload itself, so
   no options are needed to open data sealed with either KDF. Raises an error
   when the input is not a sealed payload or when its padding is invalid, which
   is how a wrong key is reported.

   #:args
     payload: The Base64-encoded, AES256-encrypted string to decrypt.
     k: The decryption key (a string) that was used to encrypt the payload.

   #:returns
     The original, decrypted data as a string.

   #:example
     (decrypt-payload \"U2FsdGVkX1+...\" \"mysecretkey\")"
  (kdf-decrypt payload k))

(define* (seal-authenticated-body plaintext encryption-key signing-key
                                  #:key (kdf default-kdf) associated-data)
  "Seal @var{plaintext} into the body of a BWK3 envelope, as Base16.

   The plaintext is first encrypted under the encryption key with AES-256-CBC,
   in the OpenSSL-compatible payload layout, and garbled. That inner payload is
   then sealed with AES-256-GCM under a key derived from the signing key with
   @var{kdf}, and the tag covers @var{associated-data} — the envelope header —
   as well as the ciphertext, so the header cannot be altered without the body
   failing to open."
  (let* ((inner (string-trim-right (encrypt-payload plaintext encryption-key
                                                    #:kdf kdf)))
         (garbled (string-garble inner)))
    (gcm-encrypt (string->utf8 garbled) signing-key #:kdf kdf
                 #:associated-data associated-data)))

(define* (open-authenticated-body body encryption-key signing-key
                                  #:key associated-data)
  "Reverse `seal-authenticated-body`, returning the original plaintext string.

   @var{associated-data} must be the envelope header the body was sealed with.
   The GCM tag is checked before anything is decrypted, so a wrong key, an
   altered body or an altered header all raise here without returning a
   plaintext."
  (let* ((garbled (utf8->string (gcm-decrypt body signing-key
                                             #:associated-data
                                             associated-data)))
         (inner (string-ungarble garbled)))
    (decrypt-payload inner encryption-key)))

;; ====== Versioned, authenticated envelope ======
;;
;; Sealed tokens and objects use a self-describing envelope whose header carries
;; rotation metadata:
;;
;;     BWK3.<key-id>.<created-at>.<expires-at>.<body>
;;
;; where
;;   - <key-id>     identifies which key sealed the data (key rotation),
;;   - <created-at> is the Unix timestamp (seconds) at sealing time,
;;   - <expires-at> is the Unix timestamp after which the data must not be
;;                  opened, or "-" when it never expires,
;;   - <body>       is an authenticated sealed payload, Base16-encoded.
;;
;; The integrity of the envelope comes from the cipher itself: the body is
;; sealed with AES-256-GCM under a key derived from the signing key, and the
;; four header fields above are handed to the cipher as associated data. One tag
;; therefore covers the ciphertext *and* the metadata, so there is no separate
;; MAC and no second MAC key; the header cannot be read as authentic before the
;; cipher has accepted it, and a refused tag means no plaintext is ever
;; returned. The metadata can still be listed without any key, for auditing
;; (`envelope-metadata`, `envelope-expired?`).
;;
;; BWK3 is the only version this module produces *and* the only one it reads.
;; There is no reader for the earlier MAC-authenticated formats, no MAC key to
;; provision, and no bare pre-versioning Base16 token: anything that is not a
;; well-formed BWK3 envelope is refused rather than guessed at. Data sealed by
;; an earlier release has to be re-sealed with `seal-envelope` or a fresh
;; `generate-token`.

(define seal-format-version
  "BWK3")

;; The versions `open-envelope' accepts. Only the current one: the list exists
;; so an operator or a caller can ask the library what it supports instead of
;; assuming, and so a future version can extend it deliberately.
(define readable-seal-format-versions
  (list seal-format-version))

(define no-expiry-marker
  "-")

(define default-key-id
  "default")

(define (valid-key-id? key-id)
  "Return #t when @var{key-id} is a non-empty label without dots or whitespace,
   so that it can be embedded in the dot-separated envelope header."
  (and (string? key-id)
       (> (string-length key-id) 0)
       (not (string-contains key-id "."))
       (not (string-any char-set:whitespace key-id))))

(define (sealed-envelope? sealed)
  "Return #t when @var{sealed} is a bewaking envelope of any readable format
   version."
  (and (string? sealed)
       (any (lambda (version)
              (string-prefix? (string-append version ".") sealed))
            readable-seal-format-versions)
       #t))

(define (parse-expires-at raw)
  "Return the expiry timestamp recorded in the envelope field @var{raw}, or #f
   for the no-expiry marker. Raises an error when the field is neither."
  (if (string=? raw no-expiry-marker)
      #f
      (let ((expires (string->number raw)))
        (unless (integer? expires)
          (error (format #f "bewaking: malformed ~a envelope (expires-at)"
                         seal-format-version)))
        expires)))

(define (parse-envelope sealed)
  "Parse a BWK3 envelope into an alist with @code{version}, @code{key-id},
   @code{created-at}, @code{expires-at} and @code{body}.

   Raises an error when the value is not a BWK3 envelope, or when its structure
   is malformed. No other format version is understood."
  (unless (and (string? sealed)
               (string-prefix? (string-append seal-format-version ".") sealed))
    (error
     (format #f "bewaking: not a bewaking envelope (expected ~a)."
             seal-format-version)))
  (let ((parts (string-split sealed #\.)))
    (unless (= (length parts) 5)
      (error (format #f "bewaking: malformed ~a envelope" seal-format-version)))
    (let ((created-at (string->number (list-ref parts 2))))
      (unless (integer? created-at)
        (error
         (format #f "bewaking: malformed ~a envelope (created-at)"
                 seal-format-version)))
      (list (cons 'version seal-format-version)
            (cons 'key-id (list-ref parts 1))
            (cons 'created-at created-at)
            (cons 'expires-at (parse-expires-at (list-ref parts 3)))
            (cons 'body (list-ref parts 4))))))

(define (envelope-header info)
  "Build the part of an envelope that precedes its body, from a parsed envelope
   alist as returned by `parse-envelope`.

   This exact string is the associated data covered by the cipher tag, so
   rebuilding it from parsed values and feeding it back to the cipher is what
   binds the metadata to the payload."
  (let ((key-id (assoc-ref info 'key-id))
        (created-at (assoc-ref info 'created-at))
        (expires-at (assoc-ref info 'expires-at)))
    (format #f "~a.~a.~a.~a" seal-format-version key-id created-at
            (or expires-at no-expiry-marker))))

(define* (envelope-metadata #:key sealed)
  "Return an alist of envelope metadata without needing any key:
   @code{version}, @code{key-id}, @code{created-at} and @code{expires-at}.

   @code{expires-at} is #f when the data never expires. Returns #f when
   @var{sealed} is not a well-formed envelope.

   Reading this needs no key, which is what makes it useful for auditing; the
   metadata is authenticated by the envelope's cipher tag, so `open-envelope`
   will not act on it before that protection has been accepted. Treat this
   function's result as a *claim* to log, never as a decision: only
   `open-envelope` can say whether the envelope is genuine."
  (unless sealed
    (error "envelope-metadata: The 'sealed' was not found."))
  (if (sealed-envelope? sealed)
      ;; A malformed envelope is not metadata, and an audit helper must not turn
      ;; an unparseable input into an exception. #f means "nothing readable
      ;; here", which is also the wrong thing to log and the right reason to
      ;; refuse the value everywhere else.
      (catch #t
             (lambda ()
               (let ((info (parse-envelope sealed)))
                 (list (cons 'version (assoc-ref info 'version))
                       (cons 'key-id (assoc-ref info 'key-id))
                       (cons 'created-at (assoc-ref info 'created-at))
                       (cons 'expires-at (assoc-ref info 'expires-at)))))
             (lambda (key . args) #f))
      #f))

(define* (envelope-expired? #:key sealed (now (current-time)))
  "Return #t when @var{sealed} is an envelope carrying an @code{expires-at} in the
   past relative to @var{now}, and #f otherwise — including envelopes with no
   expiry and non-envelope values.

   This is an unauthenticated audit helper that reads the header only. Use
   `open-envelope`, which verifies the cipher tag, to enforce expiry during
   decryption."
  (let ((metadata (envelope-metadata #:sealed sealed)))
    (if metadata
        (let ((expires-at (assoc-ref metadata 'expires-at)))
          (and expires-at (> now expires-at)))
        #f)))

(define (check-envelope-freshness info enforce-expiry? now max-age-seconds)
  "Raise an error when the envelope described by @var{info} has expired, or is
   older than @var{max-age-seconds}.

   Only call this once the envelope's integrity has been verified: it acts on
   the metadata, which is only trustworthy once the cipher tag has been
   accepted."
  (let ((expires-at (assoc-ref info 'expires-at))
        (created-at (assoc-ref info 'created-at))
        (key-id (assoc-ref info 'key-id)))
    (when (and enforce-expiry? expires-at (> now expires-at))
      (error
       (format #f "open-envelope: the sealed data expired at ~a (key '~a')."
               expires-at key-id)))
    (when (and max-age-seconds created-at
               (> (- now created-at) max-age-seconds))
      (error
       (format #f
               "open-envelope: the sealed data was created at ~a, older than the allowed maximum age of ~a seconds."
               created-at max-age-seconds)))))

(define* (key-material #:key keyring key-id encryption-key signing-key
                       (now (current-time)))
  "Resolve the encryption and signing keys to use.

   When @var{keyring} is supplied it takes precedence: it must be an alist
   mapping a key id to an entry alist with `encryption-key`, `signing-key`, and
   optional `not-before` / `not-after` timestamps describing the window during
   which the key may be used. Using a key outside its window raises an error,
   which is how rotation policies are enforced. Otherwise the explicit keys are
   used. Returns two values: the encryption key and the signing key."
  (if keyring
      (let ((entry (assoc key-id keyring)))
        (unless entry
          (error
           (format #f "bewaking: no keyring entry for key id '~a'" key-id)))
        (let* ((entry-alist (cdr entry))
               (not-before (assoc-ref entry-alist 'not-before))
               (not-after (assoc-ref entry-alist 'not-after)))
          (when (and not-before (> not-before now))
            (error
             (format #f "bewaking: the key '~a' is not valid yet." key-id)))
          (when (and not-after (> now not-after))
            (error
             (format #f "bewaking: the key '~a' has been retired." key-id)))
          (values (assoc-ref entry-alist 'encryption-key)
                  (assoc-ref entry-alist 'signing-key))))
      (values encryption-key signing-key)))

(define* (seal-envelope #:key plaintext encryption-key signing-key
                        (key-id default-key-id)
                        (created-at (current-time)) expires-at ttl-seconds
                        (kdf default-kdf))
  "Seal a plaintext string into a versioned, authenticated envelope.

   The output is
   @code{BWK3.<key-id>.<created-at>.<expires-at>.<body>}, where the body is a
   sealed payload whose authenticity comes from AES-256-GCM keyed by the signing
   key. An encryption key and a signing key are all that is required: there is
   no MAC key, because the cipher tag is the integrity check.

   #:key created-at:  Unix timestamp to record (default: now).
   #:key expires-at:  Unix timestamp after which the data must not be opened.
   #:key ttl-seconds: convenience; sets expires-at to created-at + ttl-seconds.
                      Give at most one of expires-at / ttl-seconds.
   #:key kdf:         how the AES keys are derived from the two keys, either a
                      symbol such as @code{'pbkdf2} (the default) or
                      @code{'argon2id}, or an alist of parameters as accepted
                      by @code{kdf-spec} in @code{(bewaking crypto)}. The
                      choice is recorded in the sealed body, so opening needs
                      no matching option.

   #:example
     (seal-envelope #:plaintext some-plaintext #:encryption-key k1
                    #:signing-key k2 #:ttl-seconds (* 24 3600))
     (seal-envelope #:plaintext some-plaintext #:encryption-key k1
                    #:signing-key k2 #:kdf 'argon2id)"
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
  (let* ((effective-expires (cond (expires-at expires-at)
                                  (ttl-seconds (+ created-at ttl-seconds))
                                  (else #f)))
         ;; The header is built first because the cipher authenticates it: it is
         ;; the associated data of the body that follows it.
         (header (format #f "~a.~a.~a.~a" seal-format-version key-id created-at
                         (or effective-expires no-expiry-marker)))
         (body (seal-authenticated-body plaintext encryption-key signing-key
                                        #:kdf kdf
                                        #:associated-data
                                        (string->utf8 header))))
    (format #f "~a.~a" header body)))

;; ====== The one refusal an unopenable envelope gets ======
;;
;; Every "we could not open this" answer is the same message. The key id
;; travels in the clear, so anybody can put any label in a token and watch how
;; the attempt is refused; if an unknown label failed differently from a bad
;; tag, the refusal itself would enumerate which key ids a deployment
;; configures — the reconnaissance that key rotation is meant to be invisible
;; to. So an unknown key id, a retired one, one that is not active yet, a wrong
;; key and altered data are one answer, on every surface: the library's error,
;; what `decrypt-token' prints, the CLI's message and its exit code.
(define envelope-refusal-message
  "bewaking: the sealed data could not be opened: unknown, retired or wrong key, or the data was altered.")

(define (refuse-unreadable-envelope)
  "Raise the one refusal shared by every failure to open an envelope."
  (error envelope-refusal-message))

(define (unresolved-key-placeholder)
  "Return a key that is guaranteed not to be a usable one.

   When an envelope names a key id the keyring cannot resolve, opening does not
   stop early: it continues with this key and fails at the cipher tag, exactly
   as a wrong key does. That keeps two things true at once. A retired key still
   opens nothing. And an attacker probing with key ids cannot use *how much work*
   the attempt cost, or which error came back, to learn which ids exist. The
   value is drawn fresh each time, so it can never coincide with a real key."
  (base16-encode (random-bytes 32)))

(define* (usable-key-material #:key keyring key-id encryption-key signing-key
                              now)
  "Return the encryption and signing keys to attempt an envelope with: the
   keyring's pair when @var{key-id} resolves to an entry usable at @var{now},
   and a freshly drawn placeholder otherwise.

   Failing to resolve is not an error here, deliberately. Opening with a key
   that cannot be right fails at the cipher tag, which is what a wrong key does,
   so an unknown, retired or not-yet-active key id is indistinguishable from a
   bad key — in the message returned and in the work spent producing it."
  (let ((resolved
         (catch #t
           (lambda ()
             (call-with-values
                 (lambda ()
                   (key-material #:keyring keyring #:key-id key-id
                                 #:encryption-key encryption-key
                                 #:signing-key signing-key #:now now))
               (lambda (encryption signing)
                 ;; An entry that is missing a key is as unusable as no entry.
                 (and encryption signing (cons encryption signing)))))
           (lambda (key . args) #f))))
    (if resolved
        (values (car resolved) (cdr resolved))
        (values (unresolved-key-placeholder)
                (unresolved-key-placeholder)))))

(define* (open-envelope #:key sealed encryption-key signing-key keyring
                        (enforce-expiry? #t) (now (current-time))
                        max-age-seconds)
  "Open a sealed envelope and return its plaintext string.

   The envelope is opened with AES-256-GCM, whose tag also covers the rotation
   metadata (key id, created-at, expires-at): no plaintext is returned unless
   the tag verifies, so the metadata cannot be read as authentic before the
   cipher has accepted it, and tampering is refused rather than decrypted and
   then distrusted.

   A refusal is deliberately unspecific. An unknown key id, a retired key, a
   key that is not active yet, a wrong key and altered data all raise the same
   error, and the attempt is made with a placeholder key rather than abandoned
   early, so the work done is comparable too. See `envelope-refusal-message'.
   Expiry is the one distinguishable case, because it is only reached once the
   tag has proved the envelope genuine, and an operator needs to know that live
   data merely went stale.

   #:key enforce-expiry?: when #t (the default) an envelope whose
                         @code{expires-at} is in the past is rejected.
   #:key now:             current Unix timestamp, for deterministic checks.
   #:key max-age-seconds: optional; reject envelopes created longer ago than this.
   #:key keyring:         optional alist of key id to key entry; the entry's
                         @code{not-before} / @code{not-after} window is enforced.

   Anything that is not a well-formed BWK3 envelope — an envelope of an earlier
   format version, a pre-versioning bare Base16 token, or arbitrary text — is
   refused."
  (unless sealed
    (error "open-envelope: The 'sealed' was not found."))
  (unless (sealed-envelope? sealed)
    (error
     (format #f "open-envelope: not a bewaking envelope (expected ~a)."
             (string-join readable-seal-format-versions ", "))))
  (let* ((info (parse-envelope sealed))
         (key-id (assoc-ref info 'key-id))
         (body (assoc-ref info 'body))
         ;; Resolving the keys and opening the body answer with the single
         ;; refusal above. The freshness checks stay outside this catch on
         ;; purpose: they run on values whose authenticity has already been
         ;; established, so telling an operator "this expired" reveals nothing
         ;; an attacker could not already see in the envelope's own header.
         (plaintext
          (catch #t
            (lambda ()
              (let-values (((encryption signing)
                            (usable-key-material
                             #:keyring keyring #:key-id key-id
                             #:encryption-key encryption-key
                             #:signing-key signing-key #:now now)))
                ;; The tag is checked while the body is opened, so a plaintext
                ;; exists only once the metadata has proved authentic.
                (open-authenticated-body
                 body encryption signing
                 #:associated-data (string->utf8 (envelope-header info)))))
            (lambda (key . args) (refuse-unreadable-envelope)))))
    (check-envelope-freshness info enforce-expiry? now max-age-seconds)
    plaintext))

(define* (unsafe-generate-token #:key encryption-key signing-key keyring
                                (key-id default-key-id)
                                get-owner-details
                                (token-validity-seconds (* 7 24 3600))
                                ttl-seconds expires-at (kdf default-kdf))
  "Generates a secure, versioned, authenticated token.

  #:key encryption-key:   The secret key (string) used for AES-256 encryption.
  #:key signing-key:      The signing key (string) used to derive the key of
                          the AES-256-GCM layer that authenticates the token.
  #:key keyring:          Optional alist of key-id -> key entry used to select
                          keys instead of the explicit keys above.
  #:key key-id:           Key identifier embedded in the envelope (default
                          \"default\"). Enables key rotation.
  #:key get-owner-details: A thunk that returns an the owner's details.
  #:key token-validity-seconds: The token's payload lifetime in seconds.
  #:key ttl-seconds:      Optional envelope lifetime in seconds. When given, the
                          sealed envelope records an expiry and `decrypt-token`
                          refuses to open it afterwards (default: no expiry).
  #:key expires-at:       Optional Unix timestamp for the envelope expiry;
                          mutually exclusive with ttl-seconds.
  #:key kdf:              How the AES keys are derived from the two keys. Use
                          @code{'argon2id} for a memory-hard derivation; the
                          default is PBKDF2, which is what older tokens use.
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
    (let-values (((effective-encryption-key effective-signing-key)
                  (key-material #:keyring keyring #:key-id key-id
                                #:encryption-key encryption-key
                                #:signing-key signing-key)))
      (unless effective-encryption-key
        (error
         "generate-token: The #:encryption-key keyword argument is required."))
      (unless effective-signing-key
        (error
         "generate-token: The #:signing-key keyword argument is required."))
      (seal-envelope #:plaintext base64-payload
                     #:encryption-key effective-encryption-key
                     #:signing-key effective-signing-key
                     #:key-id key-id
                     #:ttl-seconds ttl-seconds #:expires-at expires-at
                     #:kdf kdf))))

(define* (unsafe-decrypt-token #:key token encryption-key signing-key
                               keyring
                               (enforce-expiry? #t) max-age-seconds
                               (now (current-time)))
  "Decodes and validates a secure token created by `generate-token`.

  Tokens carry a version tag, a key id and an authentication tag inside the
  sealed body. The tag is checked *while* the token is opened, so tampering is
  reported explicitly and no plaintext exists before authenticity is
  established. Anything that is not a current-version envelope is refused.

  All cryptography is performed in this process (see the module
  `(bewaking crypto)`); no external command-line tools are involved.

  #:key token:          The token string to decrypt.
  #:key encryption-key: The key used for the inner AES-256 encryption.
  #:key signing-key:    The key whose derived AES-256-GCM layer authenticates
                        the envelope.
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

(define* (decrypt-token #:key token encryption-key signing-key keyring
                        (enforce-expiry? #t) max-age-seconds)
  "Safely attempts to decrypt a given token.
   This function acts as a wrapper around `unsafe-decrypt-token`,
   catching any errors that occur during the decryption process.

   Args:
     token: The token string to be decrypted.
     encryption-key: The key used for encryption.
     signing-key: The key whose derived AES-256-GCM layer authenticates the
                  envelope.
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
                                 #:keyring keyring
                                 #:enforce-expiry? enforce-expiry?
                                 #:max-age-seconds max-age-seconds))
         (lambda (key . args)
           (display (format #f "error decrypting token: ~a: ~a" key args)) #f)))

(define* (generate-token #:key encryption-key signing-key keyring (key-id default-key-id)
                         get-owner-details
                         (token-validity-seconds (* 7 24 3600))
                         ttl-seconds expires-at (kdf default-kdf))
  "Safely attempts to generate a new token.
   This function wraps `unsafe-generate-token` to gracefully handle
   any potential errors during token creation.

   Args:
     encryption-key: The key to be used for encrypting the token's payload.
     signing-key: The key to be used for signing the token.
     keyring: (Optional) alist of key-id -> key entry for key rotation.
     key-id: (Optional) label embedded in the envelope (default \"default\").
     get-owner-details: A thunk that returns a list of details about the token's owner.
     token-validity-seconds: (Optional) The payload validity duration in seconds.
     ttl-seconds: (Optional) Envelope lifetime in seconds; seals an expiry into the token.
     expires-at: (Optional) Explicit Unix timestamp for the envelope expiry.
     kdf: (Optional) Key-derivation specification; 'pbkdf2 (the default) or
          'argon2id, or an alist of parameters. Recorded in the token itself.

   Returns:
     A newly generated token string if successful, otherwise `#f`
     (false) and prints an error message to the console."
  (catch #t
         (lambda ()
           (unsafe-generate-token #:encryption-key encryption-key
                                  #:signing-key signing-key
                                  #:keyring keyring
                                  #:key-id key-id
                                  #:get-owner-details get-owner-details
                                  #:token-validity-seconds
                                  token-validity-seconds
                                  #:ttl-seconds ttl-seconds
                                  #:expires-at expires-at
                                  #:kdf kdf))
         (lambda (key . args)
           (display (format #f "Couldn't generate token: ~a: ~a" key args)) #f)))

(define* (unsafe-encrypt-object #:key payload encryption-key signing-key
                                keyring (key-id default-key-id)
                                ttl-seconds expires-at (kdf default-kdf))
  "Seal an arbitrary Scheme datum (not just a token payload) into a portable,
   versioned, authenticated string. Any value that `write` can serialize is
   supported: alists, lists, vectors, numbers, strings, booleans, etc.

   #:key payload: The Scheme datum to protect.
   #:key encryption-key: The inner AES-256 key (string). Required unless a
                         keyring is supplied.
   #:key signing-key: The key (string) whose derived AES-256-GCM layer
                 authenticates the envelope.
   #:key keyring: Optional alist of key-id -> key entry for key rotation.
   #:key key-id: Key identifier embedded in the envelope (default \"default\").
   #:key ttl-seconds: Optional envelope lifetime in seconds. The envelope then
                 records an expiry and refuses to reopen afterwards.
   #:key expires-at: Optional Unix timestamp for the envelope expiry; mutually
                 exclusive with ttl-seconds.
   #:key kdf: How the AES keys are derived from the two keys: 'pbkdf2 (the
                 default) or 'argon2id, or an alist of parameters as accepted
                 by `kdf-spec`. The choice travels inside the sealed body.
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
  (let-values (((effective-encryption-key effective-signing-key)
                (key-material #:keyring keyring #:key-id key-id
                              #:encryption-key encryption-key
                              #:signing-key signing-key)))
    (unless effective-encryption-key
      (error "encrypt-object: The 'encryption-key' was not found."))
    (unless effective-signing-key
      (error "encrypt-object: The 'signing-key' was not found."))
    (seal-envelope #:plaintext (base64-encode (serialize-payload payload))
                   #:encryption-key effective-encryption-key
                   #:signing-key effective-signing-key
                   #:key-id key-id
                   #:ttl-seconds ttl-seconds #:expires-at expires-at
                   #:kdf kdf)))

(define* (encrypt-object #:key payload encryption-key signing-key
                         keyring (key-id default-key-id)
                         ttl-seconds expires-at (kdf default-kdf))
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
                                  #:ttl-seconds ttl-seconds
                                  #:expires-at expires-at
                                  #:kdf kdf))
         (lambda (key . args)
           (display (format #f "Couldn't encrypt object: ~a: ~a" key args)) #f)))

(define* (unsafe-decrypt-object #:key object encryption-key signing-key
                                keyring
                                (enforce-expiry? #t) max-age-seconds
                                (now (current-time)))
  "Reopen a string produced by `unsafe-encrypt-object`, returning the original
   Scheme datum. The envelope's authentication tag is checked as it is opened,
   so tampering is reported explicitly and no plaintext exists before that
   check. Raises an error if the object cannot be decrypted.

   #:key object: The sealed string to decrypt.
   #:key encryption-key: The inner AES-256 key (string).
   #:key signing-key: The key whose derived AES-256-GCM layer authenticates the
                 envelope.
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
                         keyring
                         (enforce-expiry? #t) max-age-seconds)
  "Safely reopen a string produced by `encrypt-object`. Wraps
   `unsafe-decrypt-object`, catching errors and returning #f instead of raising.

   See `unsafe-decrypt-object` for the keyword arguments."
  (catch #t
         (lambda ()
           (unsafe-decrypt-object #:object object
                                  #:encryption-key encryption-key
                                  #:signing-key signing-key
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
