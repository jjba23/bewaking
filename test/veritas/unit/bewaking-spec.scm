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
  #:use-module (bewaking crypto)
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

(define (raises? thunk)
  "Return #t when calling the zero-argument @var{thunk} raises, else #f."
  (catch #t (lambda () (thunk) #f) (lambda args #t)))

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

;; ====== Frozen envelopes of the earlier format versions ======
;;
;; These strings were sealed by the released code from *before* version 3
;; existed (commit 4ffd244), with the two keys above and the key id "2026a",
;; and are kept verbatim here. They used to be opened for compatibility; now
;; the module reads only BWK3, so they are kept as *rejection* fixtures: every
;; one of them must be refused, with no plaintext and no metadata, exactly like
;; arbitrary text. That way a reintroduced reader for an old format would fail
;; the suite instead of slipping in.
;;
;;   BWK1 carries no timestamps and authenticates with an HMAC over
;;   "BWK1.<key-id>.<body>"; BWK2 adds the two timestamps to header and MAC.
;;
;; They are also the realistic thing an attacker would paste at a token API, so
;; they double as "pasted someone else's old token" coverage.

(define bwk1-envelope
  "BWK1.2026a.3d3d777446656270514d637a49705634384c6c4e426a7a306f6d31314f6c6749434a464456574d2b7a78334965726c306e69364f65543745716e6d4d774947323348527536564e5844523777372b31586b56476473463255.5127137487dd307f4e0a4d69c06706983944369f0200166d500e0988f466982a")

(define bwk2-envelope
  "BWK2.2026a.1791715315.1791718915.3d3d774f3141672b664b4e6b77436a364939715936726c6b4e6e4d334c41476d744a37445a5831483663482b4e7a76653174626d556a2f426d4f647779384e773066495476422b4141794265312f31586b56476473463255.acb8a942c0cb195c275de2d89b4c984479437f1f6d62a097650fb395087e8ae1")

(define bwk2-no-expiry-envelope
  "BWK2.2026a.1791715315.-.3d3d77512f794e4d546b45364f5a624263347749386a4f574a447267354e72574d774c512b2b6f6732445a3647744373696c62756a4a5875724e5544754369664d57443432484a4643316f45383831586b56476473463255.e4fdbe668517e8a1e3f08b1f1c1c03d2b126df8e17c8d3967a17b051b9e455c3")

;; A bare, pre-versioning Base16 token (the shape the CLI used to emit).
(define bare-base16-token
  "3d4d714938487a384a56717573394169")


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
                             #:name "round-trips a list payload"))
         (test "decrypted data is data, never code"
               ;; The payload is parsed with `read', which does not evaluate.
               ;; Guile's `#.' read-eval syntax is off by default, so a sealed
               ;; value that *looks* like a program comes back as the string it
               ;; was sealed as — knowing the format buys no code execution.
               (assert-true (raises? (lambda ()
                                       (read (open-input-string "#.(+ 1 2)"))))
                            #:name "Guile refuses the #. read-eval syntax")
               (assert-equal #:expect "#.(+ 1 2)"
                             #:got (decrypt-object
                                    #:object (encrypt-object
                                              #:payload "#.(+ 1 2)"
                                              #:encryption-key
                                              some-valid-encryption-key
                                              #:signing-key
                                              some-valid-signing-key)
                                    #:encryption-key
                                    some-valid-encryption-key
                                    #:signing-key
                                    some-valid-signing-key)
                             #:name "a sealed payload that looks like code stays a string"))))

(define (tamper-hex-at s i)
  "Return @var{s} with the character at index @var{i} replaced by a different
   hexadecimal digit, to simulate tampering."
  (let* ((ch (string-ref s i))
         (replacement (if (char=? ch #\0) #\1 #\0))
         (prefix (substring s 0 i))
         (suffix (substring s (+ i 1) (string-length s))))
    (string-append prefix (string replacement) suffix)))

(define (refusal-text thunk)
  "Return the text of the error @var{thunk} raises, or the string \"(no error)\"
   when it returns at all, so that two refusals can be compared with
   =assert-equal= instead of merely both being known to raise."
  (catch #t (lambda () (thunk) "(no error)")
         (lambda args (format #f "~a" args))))

;; ====== The refusal must not enumerate the keyring ======
;;
;; A key id travels in the clear, so an attacker can put any label in a token and
;; watch how the attempt is refused. If an unknown label failed differently from
;; a bad tag — or if the message merely named the label — the refusal would tell
;; them which key ids a deployment configures. Every "we could not open this"
;; cause therefore has to produce one identical answer.

(define atomic-keyring
  '( ("2026a" (encryption-key . "enc-2026a-a")
               (signing-key . "sig-2026a-a"))))

(define (keyring-with-window extra)
  `(("2026a" (encryption-key . "enc-2026a-a")
             (signing-key . "sig-2026a-a")
             ,@extra)))

(define (keyring-sealed-object)
  (encrypt-object #:payload '((v . 1)) #:keyring atomic-keyring
                  #:key-id "2026a"))

(define (relabel-key-id sealed key-id)
  "Return @var{sealed} with its key id replaced by @var{key-id}, as an attacker
   probing with a made-up label would."
  (string-replace-substring sealed "BWK3.2026a."
                            (string-append "BWK3." key-id ".")))

(define (open-by-keyring sealed keyring now)
  (open-envelope #:sealed sealed #:keyring keyring #:now now))

(define (key-id-nobody-configured)
  "a-label-nobody-configured")

(define (unknown-key-id-refusal)
  (refusal-text
   (lambda ()
     (open-by-keyring (relabel-key-id (keyring-sealed-object)
                                      (key-id-nobody-configured))
                      atomic-keyring 1000))))

(define (missing-entry-refusal)
  (refusal-text
   (lambda ()
     (open-by-keyring (keyring-sealed-object)
                      '( ("other" (encryption-key . "e")
                                  (signing-key . "s")))
                      1000))))

(define (retired-key-refusal)
  (refusal-text
   (lambda ()
     (open-by-keyring (keyring-sealed-object)
                      (keyring-with-window '((not-after . 1000)))
                      2000))))

(define (inactive-key-refusal)
  (refusal-text
   (lambda ()
     (open-by-keyring (keyring-sealed-object)
                      (keyring-with-window '((not-before . 9999999999)))
                      1))))

(define (tampered-body-refusal)
  (let ((sealed (keyring-sealed-object)))
    (refusal-text
     (lambda ()
       (open-envelope
        #:sealed (tamper-hex-at sealed (quotient (string-length sealed) 2))
        #:keyring atomic-keyring #:now 1000)))))

(define (expired-refusal)
  ;; The deliberate exception: this is only reached once the tag has proved the
  ;; envelope genuine, so an operator can be told that live data went stale
  ;; without telling an attacker anything the header does not already show.
  (refusal-text
   (lambda ()
     (open-envelope
      #:sealed (seal-envelope #:plaintext "x"
                              #:encryption-key some-valid-encryption-key
                              #:signing-key some-valid-signing-key
                              #:expires-at 1000)
      #:encryption-key some-valid-encryption-key
      #:signing-key some-valid-signing-key))))

(define (sealed-envelope-example)
  (seal-envelope #:plaintext "top secret payload"
                 #:encryption-key some-valid-encryption-key
                 #:signing-key some-valid-signing-key))

(define (envelope-round-trip-value)
  (open-envelope #:sealed (sealed-envelope-example)
                 #:encryption-key some-valid-encryption-key
                 #:signing-key some-valid-signing-key))

(define (tampered-envelope-rejected?)
  (let ((sealed (sealed-envelope-example)))
    (raises? (lambda ()
               (open-envelope #:sealed (tamper-hex-at
                                        sealed
                                        (quotient (string-length sealed) 2))
                              #:encryption-key some-valid-encryption-key
                              #:signing-key some-valid-signing-key)))))

(define (wrong-signing-key-rejected?)
  (raises? (lambda ()
             (open-envelope #:sealed (sealed-envelope-example)
                            #:encryption-key some-valid-encryption-key
                            #:signing-key "some-other-signing-key"))))

(define (tampered-header-rejected? sealed index value)
  "Return #t when replacing envelope field @var{index} with @var{value} makes
   the envelope impossible to open, i.e. when that field is authenticated."
  (raises? (lambda ()
             (open-envelope #:sealed (with-envelope-field sealed index value)
                            #:encryption-key some-valid-encryption-key
                            #:signing-key some-valid-signing-key))))

(define (mutated-envelope-rejected? sealed)
  "Return #t when no ciphertext-shaped mutation of @var{sealed} can be opened.

   Every non-marker digit of the value is flipped in turn; with the source code
   public, that is the cheapest forgery attempt there is — take a genuine
   token and edit it. Each mutation must be refused."
  (let loop ((index 0))
    (cond ((= index (string-length sealed)) #t)
          ((member (string-ref sealed index)
                   '(#\. #\- #\B #\W #\K #\3))
           (loop (+ index 1)))
          ((raises? (lambda ()
                      (open-envelope #:sealed (tamper-hex-at sealed index)
                                     #:encryption-key
                                     some-valid-encryption-key
                                     #:signing-key
                                     some-valid-signing-key)))
           (loop (+ index 1)))
          (else #f))))

(define (with-envelope-field sealed index value)
  "Return @var{sealed} with dot-separated field @var{index} replaced by
   @var{value}, as an attacker editing the cleartext header would."
  (let ((fields (string-split sealed #\.)))
    (list-set! fields index value)
    (string-join fields ".")))

(define (envelope-body sealed)
  "Return the sealed body of @var{sealed}, whichever version it is."
  (let ((fields (string-split sealed #\.)))
    (if (string=? (car fields) "BWK1")
        (list-ref fields 2)
        (list-ref fields 4))))

(define (mac-key-option-gone?)
  ;; Sealing and opening no longer take a MAC key. Passing one is a loud error
  ;; rather than a silently ignored security parameter.
  ;;
  ;; The call is assembled with `apply' so the compiler does not flag the
  ;; deliberately wrong arity: the extra keyword has to reach the procedure at
  ;; run time in order to be rejected, which is the whole point of the test.
  (raises? (lambda ()
             (apply open-envelope
                    (list #:sealed (sealed-envelope-example)
                          #:encryption-key some-valid-encryption-key
                          #:signing-key some-valid-signing-key
                          #:mac-key "ignored")))))

(define (same-plaintext-seals-differ?)
  ;; A fresh salt and nonce per payload: two seals of the same plaintext with
  ;; the same keys must not be equal, or an observer could tell which sessions
  ;; carry the same data.
  (let ((a (sealed-envelope-example))
        (b (sealed-envelope-example)))
    (not (string=? a b))))

(define (plaintext-absent-from-envelope?)
  ;; The documented promise is that the sealed value leaks nothing a reader of
  ;; the source could use. The cleartext payload must not appear in the
  ;; envelope, not even in its Base16 form.
  (let* ((secret "the-specific-owner-email-at-joe@example.com")
         (sealed (seal-envelope #:plaintext secret
                                #:encryption-key some-valid-encryption-key
                                #:signing-key some-valid-signing-key)))
    (and (not (string-contains sealed secret))
         (not (string-contains sealed (base16-encode secret)))
         (not (string-contains sealed (base64-encode secret))))))

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
    (and (and (string-contains sealed "BWK3.2026a.") #t)
         (equal? (decrypt-object #:object sealed #:keyring keyring) '((v . new)))
         (not (decrypt-object #:object sealed #:keyring other-keyring))
         (not (decrypt-object #:object sealed #:keyring '())))))

(define sealed-envelope-suite
  (suite "Sealed envelope (versioned, authenticated)"
         (test "seal-envelope and open-envelope"
               (assert-true (sealed-envelope? (sealed-envelope-example))
                            #:name "the result is a versioned envelope")
               (assert-true (and (string-prefix? "BWK3."
                                                 (sealed-envelope-example))
                                 #t)
                            #:name "the envelope starts with the version tag")
               (assert-equal #:expect "BWK3" #:got seal-format-version
                             #:name "the module exposes the current format version")
               (assert-equal #:expect '("BWK3")
                             #:got readable-seal-format-versions
                             #:name "BWK3 is the only version produced and read")
               (assert-equal #:expect "top secret payload"
                             #:got (envelope-round-trip-value)
                             #:name "the plaintext round-trips")
               (assert-true (tampered-envelope-rejected?)
                            #:name "a tampered envelope fails the integrity check")
               (assert-true (wrong-signing-key-rejected?)
                            #:name "a wrong signing key fails the cipher check")
               (assert-true (mac-key-option-gone?)
                            #:name "passing a MAC key to open-envelope is refused, not ignored"))

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
         (test "data that is not a BWK3 envelope is refused"
               (assert-false (sealed-envelope? "not-an-envelope")
                             #:name "arbitrary text is not an envelope")
               (assert-false (sealed-envelope? "BWK9.2026a.1.2.deadbeef")
                             #:name "an unknown envelope version is not recognised")
               (assert-true (raises? (lambda ()
                                       (open-envelope
                                        #:sealed (substring (sealed-envelope-example)
                                                            0 25)
                                        #:encryption-key
                                        some-valid-encryption-key
                                        #:signing-key
                                        some-valid-signing-key)))
                            #:name "a truncated envelope is refused when it is opened")
               (assert-true (and (sealed-envelope? "BWK3.2026a.1.2.deadbeef.abc1")
                                 #t)
                            #:name "recognition is a version-tag check, not a structure check")
               (assert-true (raises? (lambda ()
                                       (open-envelope
                                        #:sealed "BWK3.2026a.1.2.deadbeef.abc1"
                                        #:encryption-key
                                        some-valid-encryption-key
                                        #:signing-key
                                        some-valid-signing-key)))
                            #:name "a BWK3 envelope carrying an extra MAC field is refused")
               (assert-true (raises? (lambda ()
                                       (open-envelope
                                        #:sealed "BWK9.2026a.1.2.deadbeef"
                                        #:encryption-key
                                        some-valid-encryption-key
                                        #:signing-key
                                        some-valid-signing-key)))
                            #:name "an unsupported version raises rather than being guessed at")
               (assert-false (decrypt-token #:encryption-key
                                            some-valid-encryption-key
                                            #:signing-key
                                            some-valid-signing-key
                                            #:token bare-base16-token)
                             #:name "a pre-versioning bare Base16 token is refused")
               (assert-false (decrypt-object #:object bare-base16-token
                                             #:encryption-key
                                             some-valid-encryption-key
                                             #:signing-key
                                             some-valid-signing-key)
                             #:name "a bare Base16 object is refused"))
         (test "no reader is left for the earlier formats"
               ;; Versions 1 and 2 authenticated with an HMAC. Keeping a reader
               ;; around would keep that code reachable; there is none, and these
               ;; frozen artifacts are refused with no plaintext and no metadata.
               (assert-false (sealed-envelope? bwk1-envelope)
                             #:name "a BWK1 envelope is not recognised")
               (assert-false (sealed-envelope? bwk2-envelope)
                             #:name "a BWK2 envelope is not recognised")
               (assert-false (sealed-envelope? bwk2-no-expiry-envelope)
                             #:name "a BWK2 envelope with no expiry is not recognised")
               (assert-false (envelope-metadata #:sealed bwk1-envelope)
                             #:name "no metadata is read out of a BWK1 envelope")
               (assert-false (envelope-metadata #:sealed bwk2-envelope)
                             #:name "no metadata is read out of a BWK2 envelope")
               (assert-false (envelope-expired? #:sealed bwk2-envelope)
                             #:name "an unreadable envelope is never reported as live")
               (assert-false (decrypt-token #:token bwk2-envelope
                                            #:encryption-key
                                            some-valid-encryption-key
                                            #:signing-key
                                            some-valid-signing-key)
                             #:name "a BWK2 token is refused even with the keys that sealed it")
               (assert-false (decrypt-object #:object bwk1-envelope
                                             #:encryption-key
                                             some-valid-encryption-key
                                             #:signing-key
                                             some-valid-signing-key)
                             #:name "a BWK1 object is refused likewise"))
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
                                  "BWK3.rotate-1.")
                                 #t)
                            #:name "the token carries the key id"))
         ;; ====== The source code is public ======
         ;;
         ;; bewaking is free software: an attacker has the algorithms, the
         ;; layout, the constants and this test suite. What they do not have is
         ;; the two keys. These tests pin the properties that make that
         ;; distinction hold: the sealed value reveals nothing, every edit to a
         ;; genuine value is refused, and the same plaintext never seals twice.
         (test "knowing the format is not knowing the plaintext"
               (assert-true (plaintext-absent-from-envelope?)
                            #:name "the plaintext, its Base16 and its Base64 do not appear in the envelope")
               (assert-true (string-prefix? "BWK3." (sealed-envelope-example))
                            #:name "the format is not hidden, only the content is")
               (assert-equal #:expect
                             '(version key-id created-at expires-at)
                             #:got (map car (envelope-metadata
                                            #:sealed (sealed-envelope-example)))
                             #:name "the public metadata is exactly what is authenticated"))
         (test "editing a genuine envelope never yields a plaintext"
               (assert-true (mutated-envelope-rejected? (sealed-envelope-example))
                            #:name "every single-digit mutation of a real envelope is refused")
               (assert-true (mutated-envelope-rejected?
                             (encrypt-object #:payload '((role . admin))
                                             #:encryption-key
                                             some-valid-encryption-key
                                             #:signing-key
                                             some-valid-signing-key))
                            #:name "and every mutation of a real sealed object too"))
         (test "the same plaintext never seals to the same value"
               (assert-true (same-plaintext-seals-differ?)
                            #:name "a fresh salt and nonce make each envelope unique")
               (assert-false (equal? (encrypt-object #:payload '((a . 1))
                                                     #:encryption-key
                                                     some-valid-encryption-key
                                                     #:signing-key
                                                     some-valid-signing-key)
                                     (encrypt-object #:payload '((a . 1))
                                                     #:encryption-key
                                                     some-valid-encryption-key
                                                     #:signing-key
                                                     some-valid-signing-key))
                             #:name "equal objects seal to different strings"))
         (test "a refusal never says which key id the keyring configures"
               ;; One message covers every cause, so nothing about the keyring can
               ;; be read off how a token is refused. The first assertion keeps
               ;; the rest honest: without it, every comparison below would also
               ;; hold if the opens had silently *succeeded* and returned the
               ;; sentinel instead of a refusal.
               (assert-true (and (string-contains (unknown-key-id-refusal)
                                                  "could not be opened")
                                 #t)
                            #:name "the refusal is a refusal, not an accidental success")
               (assert-equal #:expect (unknown-key-id-refusal)
                             #:got (tampered-body-refusal)
                             #:name "an unknown key id and a tampered body fail identically")
               (assert-equal #:expect (unknown-key-id-refusal)
                             #:got (missing-entry-refusal)
                             #:name "a keyring with no matching entry fails identically")
               (assert-equal #:expect (unknown-key-id-refusal)
                             #:got (retired-key-refusal)
                             #:name "a retired key fails identically")
               (assert-equal #:expect (unknown-key-id-refusal)
                             #:got (inactive-key-refusal)
                             #:name "a key that is not active yet fails identically")
               (assert-false (string-contains (unknown-key-id-refusal)
                                              (key-id-nobody-configured))
                             #:name "the refusal does not name the key id it could not resolve")
               (assert-false (string-contains (unknown-key-id-refusal) "2026a")
                             #:name "and it does not name a configured key id either")
               (assert-false (string-contains (unknown-key-id-refusal) "enc-2026a-a")
                             #:name "nor does it carry any key material")
               ;; Expiry stays the one exception: it is only reached once the tag
               ;; has proved the envelope genuine.
               (assert-false (string=? (unknown-key-id-refusal) (expired-refusal))
                             #:name "an expired genuine envelope is still told apart, since it authenticated first"))))

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

;; A keyring entry is (KEY-ID (encryption-key . K) (signing-key . K)
;;               (not-before . T) (not-after . T)); the two windows are optional.
;; The keys are distinctive strings rather than UUIDs so that a test failure
;; cannot be blamed on a key being the one from the fixtures above.
(define (rotation-keyring extra)
  `(("2026a" (encryption-key . "enc-2026a")
             (signing-key . "sig-2026a")
             ,@extra)))

(define (key-with-window-works?)
  ;; Inside the window: sealing and opening both use the key. Sealing always
  ;; uses the current time, so the window is chosen to contain it.
  (let* ((keyring (rotation-keyring '((not-before . 1)
                                      (not-after . 9999999999))))
         (sealed (encrypt-object #:payload '((v . 1)) #:keyring keyring
                                 #:key-id "2026a")))
    (and (equal? '((v . 1)) (unsafe-decrypt-object #:object sealed
                                                   #:keyring keyring))
         (equal? '((v . 1)) (unsafe-decrypt-object #:object sealed
                                                   #:keyring keyring
                                                   #:now 9999999998)))))

(define (retired-key-rejected?)
  ;; Sealed with an active key, then opened after the key's not-after: the
  ;; payload is intact, so only the rotation policy can be refusing it.
  (let* ((active (rotation-keyring '()))
         (retired (rotation-keyring '((not-after . 1000))))
         (sealed (encrypt-object #:payload '((v . 1)) #:keyring active
                                 #:key-id "2026a")))
    (and (equal? '((v . 1)) (unsafe-decrypt-object #:object sealed
                                                   #:keyring active))
         (raises? (lambda ()
                    (unsafe-decrypt-object #:object sealed #:keyring retired
                                           #:now 2000))))))

(define (future-key-rejected?)
  ;; A key whose not-before is in the future must not be used to seal, even
  ;; though the data would otherwise be perfectly sealable.
  (raises?
   (lambda ()
     (unsafe-encrypt-object #:payload '((v . 1)) #:key-id "2026a"
                            #:keyring (rotation-keyring
                                       '((not-before . 9999999999)))))))

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
               (assert-equal #:expect "BWK3"
                             #:got (metadata-field (sealed-envelope-example)
                                                   'version)
                             #:name "the format version is reported")
               (assert-false (envelope-metadata #:sealed "not-an-envelope")
                             #:name "metadata is only read from envelopes")
               (assert-false (envelope-metadata #:sealed bwk1-envelope)
                             #:name "an envelope of a dropped format reports no metadata")
               (assert-false (metadata-field "BWK3.2026a.1000.-" 'version)
                             #:name "a malformed BWK3 envelope reports no metadata"))
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
         (test "the metadata is authenticated"
               ;; Version 3 has no MAC field: the header is bound to the body as
               ;; the cipher's associated data, so editing any part of it must
               ;; break the tag rather than change what the envelope means.
               (assert-true (tampered-created-at-rejected?)
                            #:name "editing created-at in a BWK3 envelope breaks its tag")
               (assert-true (tampered-header-rejected? (sealed-with-metadata) 1
                                                       "another-key-id")
                            #:name "editing the key id breaks the tag")
               (assert-true (tampered-header-rejected? (sealed-with-metadata) 3
                                                       "9999999999")
                            #:name "extending the expiry in the envelope breaks the tag")
               (assert-true (tampered-header-rejected? (sealed-with-metadata) 3
                                                       "-")
                            #:name "removing the expiry marker breaks the tag")
               (assert-true (tampered-header-rejected? (sealed-envelope-example) 0
                                                       "BWK2")
                            #:name "relabelling the version is refused")
               (assert-true (tampered-header-rejected? (sealed-envelope-example) 2
                                                       "0")
                            #:name "backdating created-at breaks the tag")
               (assert-true (tampered-header-rejected? (sealed-envelope-example) 4
                                                       "00")
                            #:name "editing the body breaks the tag"))
         (test "expired tokens and objects are refused"
               (assert-true (expired-token-rejected?)
                            #:name "a token sealed with a past expiry is refused")
               (assert-true (expired-object-rejected?)
                            #:name "an object sealed with a past expiry is refused")
               (assert-false (envelope-expired? #:sealed "not-an-envelope")
                             #:name "expiry auditing ignores non-envelopes"))
         (test "keyring validity windows enforce rotation"
               (assert-true (key-with-window-works?)
                            #:name "a key inside its window seals and opens")
               (assert-true (retired-key-rejected?)
                            #:name "a key past not-after cannot open data")
               (assert-true (future-key-rejected?)
                            #:name "a key before not-before cannot seal data")
               (assert-true (list? (envelope-metadata #:sealed
                                                      (sealed-envelope-example)))
                            #:name "no keyring is needed to read metadata"))
         (test "a malformed envelope is rejected"
               (assert-true (raises? (lambda ()
                                       (open-envelope
                                        #:sealed "BWK3.2026a.1000.-"
                                        #:encryption-key
                                        some-valid-encryption-key
                                        #:signing-key
                                        some-valid-signing-key)))
                            #:name "a missing body is refused")
               (assert-true (raises? (lambda ()
                                       (open-envelope
                                        #:sealed "BWK3.2026a.not-a-number.-.body"
                                        #:encryption-key
                                        some-valid-encryption-key
                                        #:signing-key
                                        some-valid-signing-key)))
                            #:name "a non-numeric created-at is refused")
               (assert-true (raises? (lambda ()
                                       (open-envelope
                                        #:sealed "BWK3.2026a.1000.-.not-hex"
                                        #:encryption-key
                                        some-valid-encryption-key
                                        #:signing-key
                                        some-valid-signing-key)))
                            #:name "a body that is not hexadecimal is refused")
               (assert-true (raises? (lambda ()
                                       (open-envelope
                                        #:sealed "BWK3.2026a.1000.-.abc"
                                        #:encryption-key
                                        some-valid-encryption-key
                                        #:signing-key
                                        some-valid-signing-key)))
                            #:name "a truncated body is refused")
               (assert-true (raises? (lambda ()
                                       (seal-envelope
                                        #:plaintext 'not-a-string
                                        #:encryption-key
                                        some-valid-encryption-key
                                        #:signing-key
                                        some-valid-signing-key)))
                            #:name "sealing a non-string plaintext is refused")
               (assert-true (raises? (lambda ()
                                       (seal-envelope #:plaintext "x"
                                                      #:encryption-key
                                                      some-valid-encryption-key)))
                            #:name "sealing without a signing key is refused")
               (assert-true (raises? (lambda ()
                                       (seal-envelope #:plaintext "x"
                                                      #:encryption-key "x"
                                                      #:signing-key
                                                      some-valid-signing-key
                                                      #:key-id "")))
                            #:name "an empty key id is refused"))
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

