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

(define-module (veritas unit bewaking-spec)
  #:use-module (veritas veritas)
  #:use-module (bewaking bewaking)
  #:use-module (ice-9 string-fun)
  #:use-module (uuid generate))

(set! *random-state*
      (random-state-from-platform))

(define char-pool
  (string->list "abcdefghijklmnopqrstuvwxyz0123456789"))

(define (get-random-char)
  (list-ref char-pool
            (random (length char-pool))))

(define (generate-random-string length)
  (list->string (let loop
                  ((count 0)
                   (chars '()))
                  (if (= count length)
                      (reverse chars)
                      (loop (+ count 1)
                            (cons (get-random-char) chars))))))

(define get-owner-details
  (lambda ()
    `((id . "444959d3-7a8e-455e-b608-31e35145a2fa")
      (email . "someone@jointhefreeworld.org")
      (name . "Legolas son of Thandruil")
      (permissions byggsteg:modify-permissions
                   byggsteg:job-create
                   byggsteg:job-delete
                   byggsteg:profile-create
                   byggsteg:profile-delete
                   byggsteg:user-create
                   byggsteg:user-delete))))

(define some-valid-encryption-key
  "952e0690-6c3b-4828-b191-961bf98d055c")

(define some-valid-signing-key
  "503f5869-0a3c-4460-971f-5a88662de3fc")


(define generate-token-suite
  (suite "generate-token"
         (test "works properly with correct details"
               (assert-true (let* ((get-owner-details get-owner-details)
                                   (t (generate-token #:encryption-key
                                       some-valid-encryption-key
                                       #:signing-key some-valid-signing-key
                                       #:get-owner-details get-owner-details)))
                              (display (format #f "\nowner-details: ~s\n"
                                               (get-owner-details)))
                              (display (format #f "\ngenerate-token: ~a\n" t))
                              (and (not (equal? #f t))
                                   (not (equal? "" t))
                                   (not (equal? '() t))))))))

(define (a-fresh-token)
  (generate-token #:encryption-key some-valid-encryption-key
                  #:signing-key some-valid-signing-key
                  #:get-owner-details get-owner-details))

(define decode-token-suite
  (suite "Decryption"
         (test "decrypt-token"
               (assert-false (decrypt-token #:encryption-key
                                            some-valid-encryption-key
                                            #:signing-key "some-signing-key"
                                            #:token (a-fresh-token))
                             #:name
                             "fails gracefully when signing key is not valid")
               (assert-false (decrypt-token #:encryption-key
                                            some-valid-encryption-key
                                            #:signing-key
                                            some-valid-signing-key
                                            #:token "some-token")
                             #:name "fails gracefully when token is not valid")
               (assert-true (let ((d (decrypt-token #:encryption-key
                                                    some-valid-encryption-key
                                                    #:signing-key
                                                    some-valid-signing-key
                                                    #:token (a-fresh-token))))
                              (and d
                                   (equal? (assoc-ref d 'owner-name)
                                           "Legolas son of Thandruil")
                                   (equal? (assoc-ref d 'owner-email)
                                           "someone@jointhefreeworld.org")))
                            #:name "works properly with valid token"))))

(define lossless-token-suite
  (suite "Lossless Token Decryption"
         (test "lossless-token"

               (assert-true (let* ((get-owner-details get-owner-details)
                                   (t (generate-token #:encryption-key
                                       some-valid-encryption-key
                                       #:signing-key some-valid-signing-key
                                       #:get-owner-details get-owner-details))
                                   (d (decrypt-token #:encryption-key
                                       some-valid-encryption-key
                                       #:signing-key some-valid-signing-key
                                       #:token t)))
                              (display (format #f "\nowner-details: ~s\n"
                                               (get-owner-details)))
                              (display (format #f "\ngenerate-token: ~a\n" t))
                              (display (format #f "\ndecoded: ~a\n" d))
                              (and (equal? (assoc-ref d
                                                      'owner-id)
                                           (assoc-ref (get-owner-details)
                                                      'id))
                                   (equal? (assoc-ref d
                                                      'owner-permissions)
                                           (assoc-ref (get-owner-details)
                                                      'permissions))
                                   (equal? (assoc-ref d
                                                      'owner-email)
                                           (assoc-ref (get-owner-details)
                                                      'email))))
                            #:name "works properly with correct details"))))

(define garble-ungarble-string-suite
  (suite "Garbling and Ungarbling"
         (test "garble-ungarble"
               (assert-equal #:expect "dlrow"
                             #:got (string-garble "world"))
               (assert-equal #:expect "lrow"
                             #:got (string-garble "worl"))
               (assert-equal #:expect "row"
                             #:got (string-garble "wor"))
               (assert-equal #:expect "ow"
                             #:got (string-garble "wo"))
               (assert-equal #:expect "w"
                             #:got (string-garble "w"))
               (assert-equal #:expect "dlrow olleh"
                             #:got (string-garble "hello world"))
               (assert-equal #:expect "hello world"
                             #:got (string-ungarble (string-garble
                                                     "hello world")))
               (let ((some-random-string (generate-random-string 128)))
                 (assert-equal #:expect some-random-string
                               #:got (string-ungarble (string-garble
                                                       some-random-string)))))))

(define has-needed-permissions-suite
  (suite "Permissions"
         (test "has-needed-permissions?"
               (assert-false (has-needed-permissions? #:present '()
                                                      #:needed '(admin)))
               (assert-true (has-needed-permissions? #:present '(admin)
                                                     #:needed '(admin)))
               (assert-false (has-needed-permissions? #:present '(reader)
                                                      #:needed '(admin)))
               (assert-true (has-needed-permissions? #:present '(reader admin)
                                                     #:needed '(admin)))
               (assert-true (has-needed-permissions? #:present '(admin reader)
                                                     #:needed '(admin reader)))
               (assert-true (has-needed-permissions? #:present '(reader admin)
                                                     #:needed '(admin reader)))
               (assert-false (has-needed-permissions? #:present '(reader
                                                                  legolas)
                                                      #:needed '(admin reader)))
               (assert-false (has-needed-permissions? #:present '()
                                                      #:needed '(admin reader)))

               )))

(define is-token-expired-suite
  (suite "Token expiry"
         (test "is-token-expired?"
               (assert-true (is-token-expired? #:token '((token-expires-at . 1)))
                            #:name "a token whose expiry is in the past is expired")
               (assert-false (is-token-expired? #:token
                                                `((token-expires-at . ,(+ (current-time)
                                                                          3600))))
                             #:name "a token whose expiry is in the future is not expired")
               (assert-false (is-token-expired? #:token
                                                '((token-expires-at . 999999999999)))
                             #:name "a far-future token is not expired")
               (assert-error (lambda ()
                               (is-token-expired? #:token '((token-id . "x"))))
                             #:name "a missing token-expires-at raises an error")
               (assert-error (lambda ()
                               (is-token-expired? #:token
                                                  '((token-expires-at . "soon"))))
                             #:name "a malformed token-expires-at raises an error"))))

(define token-helpers-suite
  (suite "Token validity helpers"
         (test "token-remaining-seconds and token-valid?"
               (assert-true (> (token-remaining-seconds
                                #:token `((token-expires-at . ,(+ (current-time)
                                                                 100))))
                               0)
                            #:name "remaining seconds is positive for a live token")
               (assert-true (< (token-remaining-seconds
                                #:token '((token-expires-at . 1))) 0)
                            #:name "remaining seconds is negative for an expired token")
               (assert-error (lambda ()
                               (token-remaining-seconds #:token '()))
                             #:name "a missing expiry raises an error")
               (let* ((t (generate-token #:encryption-key
                                         some-valid-encryption-key
                                         #:signing-key some-valid-signing-key
                                         #:get-owner-details get-owner-details))
                      (d (decrypt-token #:encryption-key
                                        some-valid-encryption-key
                                        #:signing-key
                                        some-valid-signing-key
                                        #:token t)))
                 (assert-true (token-valid? #:token d)
                              #:name "a freshly generated token is valid")
                 (assert-false (is-token-expired? #:token d)
                               #:name "a freshly generated token is not expired")))))

(define generic-object-suite
  (suite "Generic object encryption"
         (test "encrypt-object and decrypt-object"
               (let ((payload '((user . "joe")
                                (age . 42)
                                (roles admin editor)
                                (tags "a" "b")
                                (nested . ((x . 1) (y . 2))))))
                 (let ((sealed (encrypt-object #:payload payload
                                               #:encryption-key
                                               some-valid-encryption-key
                                               #:signing-key
                                               some-valid-signing-key)))
                   (assert-true (and (string? sealed)
                                     (> (string-length sealed) 0))
                                #:name "sealing produces a non-empty string")
                   (assert-equal #:expect payload
                                 #:got (decrypt-object #:object sealed
                                                       #:encryption-key
                                                       some-valid-encryption-key
                                                       #:signing-key
                                                       some-valid-signing-key)
                                 #:name "round-trips an arbitrary alist payload")
                   (assert-false (decrypt-object #:object sealed
                                                 #:encryption-key
                                                 some-valid-encryption-key
                                                 #:signing-key
                                                 "wrong-signing-key")
                                 #:name "fails gracefully with a wrong signing key")))
               (assert-equal #:expect "just a string"
                             #:got (decrypt-object #:object
                                                   (encrypt-object #:payload
                                                                   "just a string"
                                                                   #:encryption-key
                                                                   some-valid-encryption-key
                                                                   #:signing-key
                                                                   some-valid-signing-key)
                                                   #:encryption-key
                                                   some-valid-encryption-key
                                                   #:signing-key
                                                   some-valid-signing-key)
                             #:name "round-trips a plain string payload")
               (assert-equal #:expect 1234
                             #:got (decrypt-object #:object
                                                   (encrypt-object #:payload 1234
                                                                   #:encryption-key
                                                                   some-valid-encryption-key
                                                                   #:signing-key
                                                                   some-valid-signing-key)
                                                   #:encryption-key
                                                   some-valid-encryption-key
                                                   #:signing-key
                                                   some-valid-signing-key)
                             #:name "round-trips a number payload")
               (assert-equal #:expect '(1 2 3)
                             #:got (decrypt-object #:object
                                                   (encrypt-object #:payload '(1 2 3)
                                                                   #:encryption-key
                                                                   some-valid-encryption-key
                                                                   #:signing-key
                                                                   some-valid-signing-key)
                                                   #:encryption-key
                                                   some-valid-encryption-key
                                                   #:signing-key
                                                   some-valid-signing-key)
                             #:name "round-trips a list payload"))))

(define (tamper-hex-at s i)
  "Return @var{s} with the character at index @var{i} replaced by a different
   hexadecimal digit, to simulate tampering."
  (let* ((ch (string-ref s i))
         (replacement (if (char=? ch #\0) #\1 #\0))
         (prefix (substring s 0 i))
         (suffix (substring s (+ i 1) (string-length s))))
    (string-append prefix (string replacement) suffix)))

(define (sealed-envelope-example)
  (seal-envelope #:plaintext "top secret payload"
                 #:encryption-key some-valid-encryption-key
                 #:signing-key some-valid-signing-key))

(define (envelope-round-trip-value)
  (open-envelope #:sealed (sealed-envelope-example)
                 #:encryption-key some-valid-encryption-key
                 #:signing-key some-valid-signing-key))

(define (raises? thunk)
  "Return #t when calling the zero-argument @var{thunk} raises, else #f."
  (catch #t (lambda () (thunk) #f) (lambda args #t)))

(define (tampered-envelope-rejected?)
  (let ((sealed (sealed-envelope-example)))
    (raises? (lambda ()
               (open-envelope #:sealed (tamper-hex-at
                                        sealed
                                        (quotient (string-length sealed) 2))
                              #:encryption-key some-valid-encryption-key
                              #:signing-key some-valid-signing-key)))))

(define (wrong-mac-key-rejected?)
  (raises? (lambda ()
             (open-envelope #:sealed (sealed-envelope-example)
                            #:encryption-key some-valid-encryption-key
                            #:signing-key some-valid-signing-key
                            #:mac-key "wrong-mac-key"))))

(define (tampered-token-rejected?)
  (let* ((t (generate-token #:encryption-key some-valid-encryption-key
                            #:signing-key some-valid-signing-key
                            #:get-owner-details get-owner-details))
         (tampered (tamper-hex-at t (quotient (string-length t) 2))))
    (not (decrypt-token #:token tampered
                        #:encryption-key some-valid-encryption-key
                        #:signing-key some-valid-signing-key))))

(define (tampered-object-rejected?)
  (let* ((sealed (encrypt-object #:payload '((a . 1))
                                 #:encryption-key some-valid-encryption-key
                                 #:signing-key some-valid-signing-key))
         (tampered (tamper-hex-at sealed (quotient (string-length sealed) 2))))
    (not (decrypt-object #:object tampered
                         #:encryption-key some-valid-encryption-key
                         #:signing-key some-valid-signing-key))))

(define (keyring-rotation-works?)
  (let* ((keyring '(("2026a" (encryption-key . "enc-2026a")
                             (signing-key . "sig-2026a"))
                    ("2025b" (encryption-key . "enc-2025b")
                             (signing-key . "sig-2025b"))))
         (sealed (encrypt-object #:payload '((v . new))
                                 #:keyring keyring
                                 #:key-id "2026a"))
         (other-keyring '(("2025b" (encryption-key . "enc-2025b")
                                   (signing-key . "sig-2025b")))))
    (and (and (string-contains sealed "BWK2.2026a.") #t)
         (equal? (decrypt-object #:object sealed #:keyring keyring) '((v . new)))
         (not (decrypt-object #:object sealed #:keyring other-keyring))
         (not (decrypt-object #:object sealed #:keyring '())))))

(define sealed-envelope-suite
  (suite "Sealed envelope (versioned, authenticated)"
         (test "seal-envelope and open-envelope"
               (assert-true (sealed-envelope? (sealed-envelope-example))
                            #:name "the result is a versioned envelope")
               (assert-true (and (string-prefix? "BWK2."
                                                 (sealed-envelope-example))
                                 #t)
                            #:name "the envelope starts with the version tag")
               (assert-equal #:expect "BWK2" #:got seal-format-version
                             #:name "the module exposes the current format version")
               (assert-equal #:expect "top secret payload"
                             #:got (envelope-round-trip-value)
                             #:name "the plaintext round-trips")
               (assert-true (tampered-envelope-rejected?)
                            #:name "a tampered envelope fails the integrity check")
               (assert-true (wrong-mac-key-rejected?)
                            #:name "a wrong MAC key fails the integrity check"))
         (test "tokens and objects are envelopes and reject tampering"
               (assert-true (sealed-envelope?
                             (generate-token #:encryption-key
                                             some-valid-encryption-key
                                             #:signing-key
                                             some-valid-signing-key
                                             #:get-owner-details
                                             get-owner-details))
                            #:name "generated tokens are enveloped")
               (assert-true (sealed-envelope?
                             (encrypt-object #:payload '((a . 1))
                                             #:encryption-key
                                             some-valid-encryption-key
                                             #:signing-key
                                             some-valid-signing-key))
                            #:name "sealed objects are enveloped")
               (assert-true (tampered-token-rejected?)
                            #:name "a tampered token is rejected")
               (assert-true (tampered-object-rejected?)
                            #:name "a tampered object is rejected"))
         (test "data that is not a current-version envelope is refused"
               (assert-false (sealed-envelope? "not-an-envelope")
                             #:name "arbitrary text is not an envelope")
               (assert-false (sealed-envelope? "BWK1.2026a.deadbeef.abc123")
                             #:name "an older envelope version is not recognised")
               (assert-false (sealed-envelope? "BWK3.2026a.1.2.deadbeef.abc1")
                             #:name "an unknown envelope version is not recognised")
               (assert-true (raises? (lambda ()
                                       (open-envelope
                                        #:sealed "BWK1.2026a.deadbeef.abc123"
                                        #:encryption-key
                                        some-valid-encryption-key
                                        #:signing-key
                                        some-valid-signing-key)))
                            #:name "opening an older envelope version raises")
               (assert-false (decrypt-token #:encryption-key
                                            some-valid-encryption-key
                                            #:signing-key
                                            some-valid-signing-key
                                            #:token "3d4d714938487a384a56717573394169")
                             #:name "a pre-versioning bare Base16 token is refused")
               (assert-false (decrypt-object #:object "3d4d714938487a384a56717573394169"
                                             #:encryption-key
                                             some-valid-encryption-key
                                             #:signing-key
                                             some-valid-signing-key)
                             #:name "a bare Base16 object is refused"))
         (test "key rotation with a keyring"
               (assert-true (keyring-rotation-works?)
                            #:name "a keyring seals and opens by key id"))
         (test "the requested key id is embedded in generated tokens"
               (assert-true (and (string-contains
                                  (generate-token #:encryption-key
                                                  some-valid-encryption-key
                                                  #:signing-key
                                                  some-valid-signing-key
                                                  #:key-id "rotate-1"
                                                  #:get-owner-details
                                                  get-owner-details)
                                  "BWK2.rotate-1.")
                                 #t)
                            #:name "the token carries the key id"))))

;; ====== Envelope metadata (rotation policy and audit) ======

(define (metadata-field sealed field)
  (assoc-ref (envelope-metadata #:sealed sealed) field))

(define (sealed-with-metadata)
  (seal-envelope #:plaintext "ttl payload"
                 #:encryption-key some-valid-encryption-key
                 #:signing-key some-valid-signing-key
                 #:key-id "2026a" #:created-at 1000 #:ttl-seconds 3600))

(define (token-sealed-with-expiry)
  (generate-token #:encryption-key some-valid-encryption-key
                  #:signing-key some-valid-signing-key
                  #:get-owner-details get-owner-details
                  #:expires-at 1000))

(define (expired-token-rejected?)
  (not (decrypt-token #:token (token-sealed-with-expiry)
                      #:encryption-key some-valid-encryption-key
                      #:signing-key some-valid-signing-key)))

(define (expired-object-rejected?)
  (let ((sealed (encrypt-object #:payload '((a . 1))
                                #:encryption-key some-valid-encryption-key
                                #:signing-key some-valid-signing-key
                                #:expires-at 1000)))
    (not (decrypt-object #:object sealed
                         #:encryption-key some-valid-encryption-key
                         #:signing-key some-valid-signing-key))))

(define (tampered-created-at-rejected?)
  (raises?
   (lambda ()
     (open-envelope #:sealed (string-replace-substring (sealed-with-metadata)
                                                       "1000" "9000")
                    #:encryption-key some-valid-encryption-key
                    #:signing-key some-valid-signing-key))))

(define (retired-key-rejected?)
  (let* ((keyring '((("2026a" (encryption-key . "enc-2026a")
                             (signing-key . "sig-2026a")))))
         (sealed (encrypt-object #:payload '((v . 1)) #:keyring keyring
                                 #:key-id "2026a"))
         (retired '((("2026a" (encryption-key . "enc-2026a")
                              (signing-key . "sig-2026a")
                              (not-after . 1000))))))
    (raises? (lambda ()
               (unsafe-decrypt-object #:object sealed #:keyring retired)))))

(define (future-key-rejected?)
  (raises?
   (lambda ()
     (unsafe-encrypt-object #:payload '((v . 1)) #:key-id "2026a"
                            #:keyring '((("2026a"
                                         (encryption-key . "enc-2026a")
                                         (signing-key . "sig-2026a")
                                         (not-before . 9999999999))))))))

(define envelope-metadata-suite
  (suite "Envelope metadata (key id, created-at, expiry)"
         (test "metadata is reported without any key"
               (assert-true (integer? (metadata-field (sealed-envelope-example)
                                                      'created-at))
                            #:name "created-at is a Unix timestamp")
               (assert-equal #:expect default-key-id
                             #:got (metadata-field (sealed-envelope-example)
                                                   'key-id)
                             #:name "the key id is reported")
               (assert-false (metadata-field (sealed-envelope-example)
                                             'expires-at)
                             #:name "there is no expiry unless one was requested")
               (assert-false (envelope-metadata #:sealed
                                                "BWK1.2026a.deadbeef.abc123")
                             #:name "metadata is only read from current-version envelopes"))
         (test "ttl-seconds records an absolute expiry"
               (assert-equal #:expect 1000
                             #:got (metadata-field (sealed-with-metadata)
                                                   'created-at)
                             #:name "created-at is the requested timestamp")
               (assert-equal #:expect 4600
                             #:got (metadata-field (sealed-with-metadata)
                                                   'expires-at)
                             #:name "expires-at is created-at plus the ttl")
               (assert-false (envelope-expired? #:sealed (sealed-with-metadata)
                                                #:now 2000)
                             #:name "the envelope is live before its expiry")
               (assert-true (envelope-expired? #:sealed (sealed-with-metadata)
                                               #:now 5000)
                            #:name "the envelope is expired after its expiry"))
         (test "expiry is enforced when opening"
               (assert-true (raises? (lambda ()
                                       (open-envelope
                                        #:sealed (sealed-with-metadata)
                                        #:encryption-key some-valid-encryption-key
                                        #:signing-key some-valid-signing-key
                                        #:now 5000)))
                            #:name "an expired envelope is refused")
               (assert-equal #:expect "ttl payload"
                             #:got (open-envelope
                                    #:sealed (sealed-with-metadata)
                                    #:encryption-key some-valid-encryption-key
                                    #:signing-key some-valid-signing-key
                                    #:now 5000 #:enforce-expiry? #f)
                             #:name "enforce-expiry? #f still opens it")
               (assert-true (raises? (lambda ()
                                       (open-envelope
                                        #:sealed (sealed-with-metadata)
                                        #:encryption-key some-valid-encryption-key
                                        #:signing-key some-valid-signing-key
                                        #:now 2000 #:max-age-seconds 100)))
                            #:name "max-age-seconds enforces a rotation policy"))
         (test "the metadata is covered by the MAC"
               (assert-true (tampered-created-at-rejected?)
                            #:name "editing created-at breaks the integrity check"))
         (test "expired tokens and objects are refused"
               (assert-true (expired-token-rejected?)
                            #:name "a token sealed with a past expiry is refused")
               (assert-true (expired-object-rejected?)
                            #:name "an object sealed with a past expiry is refused")
               (assert-false (envelope-expired? #:sealed "not-an-envelope")
                             #:name "expiry auditing ignores non-envelopes"))
         (test "keyring validity windows enforce rotation"
               (assert-true (retired-key-rejected?)
                            #:name "a key past not-after cannot open data")
               (assert-true (future-key-rejected?)
                            #:name "a key before not-before cannot seal data"))
         (test "a malformed current-version envelope is rejected"
               (assert-true (raises? (lambda ()
                                       (open-envelope
                                        #:sealed "BWK2.2026a.1000.-.body"
                                        #:encryption-key
                                        some-valid-encryption-key
                                        #:signing-key
                                        some-valid-signing-key)))
                            #:name "a missing MAC field is refused")
               (assert-true (raises? (lambda ()
                                       (open-envelope
                                        #:sealed "BWK2.2026a.not-a-number.-.body.mac"
                                        #:encryption-key
                                        some-valid-encryption-key
                                        #:signing-key
                                        some-valid-signing-key)))
                            #:name "a non-numeric created-at is refused"))
         (test "invalid sealing options are rejected"
               (assert-true (raises? (lambda ()
                                       (seal-envelope
                                        #:plaintext "x"
                                        #:encryption-key some-valid-encryption-key
                                        #:signing-key some-valid-signing-key
                                        #:expires-at 20 #:ttl-seconds 10)))
                            #:name "expires-at and ttl-seconds are mutually exclusive")
               (assert-true (raises? (lambda ()
                                       (seal-envelope
                                        #:plaintext "x"
                                        #:encryption-key some-valid-encryption-key
                                        #:signing-key some-valid-signing-key
                                        #:ttl-seconds "an hour")))
                            #:name "a non-integer ttl-seconds is rejected")
               (assert-true (raises? (lambda ()
                                       (seal-envelope
                                        #:plaintext "x"
                                        #:encryption-key some-valid-encryption-key
                                        #:signing-key some-valid-signing-key
                                        #:key-id "has.a.dot")))
                            #:name "a key id containing a dot is rejected"))))

(define (spec)
  (veritas-run generate-token-suite decode-token-suite lossless-token-suite
               garble-ungarble-string-suite has-needed-permissions-suite
               is-token-expired-suite token-helpers-suite
               generic-object-suite sealed-envelope-suite
               envelope-metadata-suite))

