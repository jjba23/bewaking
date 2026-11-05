;; bewaking
;;
;; SPDX-License-Identifier: MIT
;; Copyright © Josep Bigorra <jjbigorra@gmail.com>

(define-module (veritas unit cli-spec)
  #:use-module (veritas veritas)
  #:use-module (ice-9 popen)
  #:use-module (ice-9 string-fun)
  #:use-module (ice-9 textual-ports)
  #:use-module (bewaking cli)
  #:use-module (bewaking password))

(define encryption-key "952e0690-6c3b-4828-b191-961bf98d055c")
(define signing-key "503f5869-0a3c-4460-971f-5a88662de3fc")

;; The test bodies below consist of direct `assert-*` expressions, because
;; veritas only collects assertions that appear as direct expressions in a test
;; body. Shared, multi-step flows are therefore encapsulated in the helper
;; procedures that follow and reduced to a single boolean/value per assertion.

(define (run-cli args)
  "Run the CLI with @var{args} and return a pair of (standard output . exit code).
   Standard error is discarded. The exit code is captured through a box and read
   back only after the capturing call returns, since Guile does not guarantee the
   argument evaluation order of =values=."
  (let ((box (make-vector 1 #f)))
    (let ((output (with-output-to-string
                    (lambda ()
                      (with-error-to-string
                       (lambda () (vector-set! box 0 (run args))))))))
      (cons output (vector-ref box 0)))))

(define (cli-out result) (car result))
(define (cli-code result) (cdr result))

(define (run-cli-with-error args)
  "Run the CLI with @var{args} and return a list of (standard output, standard
   error, exit code), so a test can compare what an operator — or an attacker
   reading a response and its status — actually sees. =run-cli= discards
   standard error, which is exactly where a refusal is reported."
  (let ((code (make-vector 1 #f))
        (errors (make-vector 1 #f)))
    (let ((output (with-output-to-string
                    (lambda ()
                      (vector-set! errors 0
                                   (with-error-to-string
                                    (lambda ()
                                      (vector-set! code 0 (run args)))))))))
      (list output (vector-ref errors 0) (vector-ref code 0)))))

(define (cli-refusal-state args)
  "The standard-error-and-exit-code pair a command produces, which is the whole
   of what a failure exposes."
  (let ((result (run-cli-with-error args)))
    (list (list-ref result 1) (list-ref result 2))))

(define (cli-key-id-refusals-are-uniform?)
  ;; A token sealed under one key id, opened through a keyring that knows only
  ;; that key id: once with an edited body, once with the key id relabelled to
  ;; one that keyring has never heard of. An operator must not be able to tell
  ;; those apart, because neither may an attacker: the difference would list the
  ;; key ids the deployment configures.
  (let ((keyring-file (temp-path)))
    (call-with-output-file keyring-file
      (lambda (port)
        (write `(("2026a" (encryption-key . ,encryption-key)
                          (signing-key . ,signing-key)))
               port)))
    (let* ((generated (run-cli (list "token" "generate"
                                     "--owner-id" "o1"
                                     "--keyring" keyring-file
                                     "--key-id" "2026a")))
           (token (string-trim-right (cli-out generated)))
           (tampered (flip-hex-digit token (quotient (string-length token) 2)))
           (relabelled (string-replace-substring
                        token "BWK3.2026a." "BWK3.a-label-nobody-configured."))
           (with-edited-body
            (cli-refusal-state (list "token" "decrypt" "--token" tampered
                                     "--keyring" keyring-file)))
           (with-unknown-key-id
            (cli-refusal-state (list "token" "decrypt" "--token" relabelled
                                     "--keyring" keyring-file))))
      (delete-file keyring-file)
      (and (= 0 (cli-code generated))
           (equal? with-edited-body with-unknown-key-id)
           (= 1 (cadr with-edited-body))
           (not (string-contains (car with-edited-body)
                                 "a-label-nobody-configured"))))))

(define (temp-path)
  (string-append "/tmp/bewaking-cli-"
                 (number->string (getpid))
                 "-"
                 (number->string (random 1000000))
                 ".tmp"))

(define (token-generate)
  (run-cli (list "token" "generate"
                 "--owner-id" "owner-1"
                 "--owner-name" "Joe"
                 "--owner-email" "joe@example.com"
                 "--permissions" "read,write"
                 "--encryption-key" encryption-key
                 "--signing-key" signing-key)))

(define (token-round-trip-works?)
  (let* ((generated (token-generate))
         (token (string-trim-right (cli-out generated)))
         (decrypted (run-cli (list "token" "decrypt"
                                   "--token" token
                                   "--encryption-key" encryption-key
                                   "--signing-key" signing-key))))
    (and (= 0 (cli-code generated))
         (> (string-length token) 0)
         (and (string-contains token "BWK3.") #t)
         (= 0 (cli-code decrypted))
         (and (string-contains (cli-out decrypted) "owner-id") #t)
         (and (string-contains (cli-out decrypted) "owner-1") #t))))

(define (wrong-key-rejected?)
  (let* ((generated (token-generate))
         (token (string-trim-right (cli-out generated)))
         (wrong (run-cli (list "token" "decrypt"
                               "--token" token
                               "--encryption-key" encryption-key
                               "--signing-key" "wrong-key"))))
    (= 1 (cli-code wrong))))

(define (keyring-rotation-works?)
  (let ((keyring-file (temp-path)))
    (call-with-output-file keyring-file
      (lambda (port)
        (write `(("2026a" (encryption-key . ,encryption-key)
                          (signing-key . ,signing-key))
                 ("2025b" (encryption-key . "old-enc")
                          (signing-key . "old-sign")))
               port)))
    (let* ((generated (run-cli (list "token" "generate"
                                     "--owner-id" "o1"
                                     "--keyring" keyring-file
                                     "--key-id" "2026a")))
           (token (string-trim-right (cli-out generated)))
           (opened (run-cli (list "token" "decrypt"
                                  "--token" token
                                  "--keyring" keyring-file)))
           (wrong (run-cli (list "token" "decrypt"
                                 "--token" token
                                 "--encryption-key" encryption-key
                                 "--signing-key" "wrong"))))
      (delete-file keyring-file)
      (and (= 0 (cli-code generated))
           (and (string-contains token "BWK3.2026a.") #t)
           (= 0 (cli-code opened))
           (and (string-contains (cli-out opened) "owner-id") #t)
           (= 1 (cli-code wrong))))))

(define (token-with-expiry-at timestamp)
  (run-cli (list "token" "generate"
                 "--owner-id" "owner-1"
                 "--encryption-key" encryption-key
                 "--signing-key" signing-key
                 "--expires-at" timestamp)))

(define (expired-token-refused?)
  (let* ((generated (token-with-expiry-at "1000"))
         (token (string-trim-right (cli-out generated))))
    (and (= 0 (cli-code generated))
         (and (string-contains token "BWK3.") #t)
         (= 1 (cli-code (run-cli (list "token" "decrypt"
                                       "--token" token
                                       "--encryption-key" encryption-key
                                       "--signing-key" signing-key)))))))

(define (expired-token-opened-on-request?)
  (let* ((generated (token-with-expiry-at "1000"))
         (token (string-trim-right (cli-out generated)))
         (opened (run-cli (list "token" "decrypt"
                                "--token" token
                                "--encryption-key" encryption-key
                                "--signing-key" signing-key
                                "--allow-expired"))))
    (and (= 0 (cli-code opened))
         (and (string-contains (cli-out opened) "owner-id") #t))))

(define (live-token-passes-max-age?)
  (let* ((generated (run-cli (list "token" "generate"
                                   "--owner-id" "owner-1"
                                   "--encryption-key" encryption-key
                                   "--signing-key" signing-key
                                   "--ttl-seconds" "3600")))
         (token (string-trim-right (cli-out generated))))
    (and (= 0 (cli-code generated))
         (= 0 (cli-code (run-cli (list "token" "decrypt"
                                       "--token" token
                                       "--encryption-key" encryption-key
                                       "--signing-key" signing-key
                                       "--max-age-seconds" "100000")))))))

(define (conflicting-expiry-options-rejected?)
  (= 1 (cli-code (run-cli (list "token" "generate"
                                "--owner-id" "owner-1"
                                "--encryption-key" encryption-key
                                "--signing-key" signing-key
                                "--ttl-seconds" "60"
                                "--expires-at" "1000")))))

(define (token-inspect-reports-metadata?)
  (let* ((generated (token-generate))
         (token (string-trim-right (cli-out generated)))
         (inspected (run-cli (list "token" "inspect" "--token" token))))
    (and (= 0 (cli-code inspected))
         (and (string-contains (cli-out inspected) "version:    BWK3") #t)
         (and (string-contains (cli-out inspected) "key-id:     default") #t)
         (and (string-contains (cli-out inspected) "expires-at: never") #t)
         (and (string-contains (cli-out inspected) "expired:    no") #t))))

(define (token-inspect-flags-expiry?)
  (let* ((generated (token-with-expiry-at "1000"))
         (token (string-trim-right (cli-out generated)))
         (inspected (run-cli (list "token" "inspect" "--token" token))))
    (and (= 0 (cli-code inspected))
         (and (string-contains (cli-out inspected) "expires-at: 1000") #t)
         (and (string-contains (cli-out inspected) "expired:    yes") #t))))

(define (token-inspect-rejects-non-envelope?)
  (= 1 (cli-code (run-cli (list "token" "inspect" "--token" "not-a-token")))))

(define (expired-object-refused?)
  (let ((payload-file (temp-path))
        (sealed-file (temp-path)))
    (call-with-output-file payload-file
      (lambda (port) (write '((a . 1)) port)))
    (let* ((encrypted (run-cli (list "object" "encrypt"
                                     "--input" payload-file
                                     "--encryption-key" encryption-key
                                     "--signing-key" signing-key
                                     "--expires-at" "1000"))))
      (call-with-output-file sealed-file
        (lambda (port)
          (display (string-trim-right (cli-out encrypted)) port)))
      (let ((decrypted (run-cli (list "object" "decrypt"
                                      "--input" sealed-file
                                      "--encryption-key" encryption-key
                                      "--signing-key" signing-key))))
        (delete-file payload-file)
        (delete-file sealed-file)
        (and (= 0 (cli-code encrypted))
             (= 1 (cli-code decrypted)))))))

(define (object-round-trip-works?)
  (let ((payload-file (temp-path))
        (sealed-file (temp-path)))
    (call-with-output-file payload-file
      (lambda (port) (write '((name . Joe) (score . 7)) port)))
    (let* ((encrypted (run-cli (list "object" "encrypt"
                                     "--input" payload-file
                                     "--encryption-key" encryption-key
                                     "--signing-key" signing-key))))
      (call-with-output-file sealed-file
        (lambda (port)
          (display (string-trim-right (cli-out encrypted)) port)))
      (let ((decrypted (run-cli (list "object" "decrypt"
                                      "--input" sealed-file
                                      "--encryption-key" encryption-key
                                      "--signing-key" signing-key))))
        (delete-file payload-file)
        (delete-file sealed-file)
        (and (= 0 (cli-code encrypted))
             (and (string-contains (cli-out encrypted) "BWK3.") #t)
             (= 0 (cli-code decrypted))
             (and (string-contains (cli-out decrypted) "(name . Joe)") #t)
             (and (string-contains (cli-out decrypted) "(score . 7)") #t))))))

(define dispatch-suite
  (suite "CLI dispatch"
         (test "help and exit codes"
               (assert-equal #:expect 0
                             #:got (cli-code (run-cli '("help")))
                             #:name "help exits successfully")
               (assert-true (and (string-contains
                                  (cli-out (run-cli '("help"))) "bewaking")
                                 #t)
                            #:name "help prints the usage banner")
               (assert-true (and (string-contains
                                  (cli-out (run-cli '("help"))) "token generate")
                                 #t)
                            #:name "help lists the token generate command")
               (assert-true (and (string-contains
                                  (cli-out (run-cli '("help"))) "--keyring")
                                 #t)
                            #:name "help documents the keyring option")
               (assert-true (and (string-contains
                                  (cli-out (run-cli '("help")))
                                  "--ttl-seconds")
                                 #t)
                            #:name "help documents the rotation metadata options")
               (assert-true (and (string-contains
                                  (cli-out (run-cli '("help")))
                                  "token inspect")
                                 #t)
                            #:name "help lists the token inspect command")
               (assert-equal #:expect 0
                             #:got (cli-code (run-cli '("--version")))
                             #:name "version exits successfully")
               (assert-equal #:expect 1
                             #:got (cli-code (run-cli '("bogus")))
                             #:name "an unknown command exits with 1")
               (assert-equal #:expect 1
                             #:got (cli-code (run-cli '("token")))
                             #:name "a token subcommand is required")
               (assert-equal #:expect 1
                             #:got (cli-code (run-cli '("token" "decrypt")))
                             #:name "decrypting without keys fails"))))

(define token-suite
  (suite "CLI token commands"
         (test "token round-trip"
               (assert-true (token-round-trip-works?)
                            #:name "generate then decrypt preserves the payload"))
         (test "wrong keys are rejected"
               (assert-true (wrong-key-rejected?)
                            #:name "a wrong signing key exits with 1"))
         (test "key id and keyring rotation"
               (assert-true (keyring-rotation-works?)
                            #:name "a keyring round-trips and rejects the wrong key"))))

(define object-suite
  (suite "CLI object commands"
         (test "object round-trip"
               (assert-true (object-round-trip-works?)
                            #:name "object encrypt then decrypt round-trips a datum"))
         (test "object expiry policy"
               (assert-true (expired-object-refused?)
                            #:name "an object sealed with a past expiry is refused"))))

(define rotation-metadata-suite
  (suite "CLI rotation metadata"
         (test "expiry is sealed into tokens and enforced"
               (assert-true (expired-token-refused?)
                            #:name "an expired token exits with 1")
               (assert-true (expired-token-opened-on-request?)
                            #:name "--allow-expired opens it anyway")
               (assert-true (live-token-passes-max-age?)
                            #:name "--max-age-seconds accepts fresh data")
               (assert-true (conflicting-expiry-options-rejected?)
                            #:name "--ttl-seconds and --expires-at conflict"))
         (test "token inspect audits the header without keys"
               (assert-true (token-inspect-reports-metadata?)
                            #:name "inspect reports version, key id and expiry")
               (assert-true (token-inspect-flags-expiry?)
                            #:name "inspect reports an expired envelope")
               (assert-true (token-inspect-rejects-non-envelope?)
                            #:name "inspect rejects a non-envelope token"))))

(define password-suite
  (suite "CLI password commands"
         (test "password strength"
               (assert-equal #:expect 0
                             #:got (cli-code (run-cli '("password" "strength"
                                                        "123456")))
                             #:name "strength exits successfully")
               (assert-true (and (string-contains
                                  (cli-out (run-cli '("password" "strength"
                                                      "123456")))
                                  "very weak")
                                 #t)
                            #:name "a common password is reported weak"))
         (test "password generate"
               (assert-equal #:expect 0
                             #:got (cli-code (run-cli '("password" "generate"
                                                        "--length" "32")))
                             #:name "generation exits successfully")
               (assert-equal #:expect 32
                             #:got (string-length
                                    (string-trim-right
                                     (cli-out (run-cli '("password" "generate"
                                                         "--length" "32")))))
                             #:name "the requested length is honoured")
               (assert-equal #:expect '(lowercase uppercase digit)
                             #:got (password-character-classes
                                    (string-trim-right
                                     (cli-out (run-cli '("password" "generate"
                                                         "--length" "16"
                                                         "--no-symbols")))))
                             #:name "symbols are excluded on request"))))

;; ====== Key derivation, tampering and dropped formats ======

;; A BWK2 token of the right shape: version tag, key id, timestamps, body and
;; MAC. The library only reads BWK3 now, so the CLI must refuse it rather than
;; `inspect` it as a live session or `decrypt` it with the keys that sealed it.
(define legacy-bwk2-token
  "BWK2.2026a.1791715315.1791718915.3d3d774f3141672b664b4e6b77436a364939715936726c6b4e6e4d334c41476d744a37445a5831483663482b4e7a76653174626d556a2f426d4f647779384e773066495476422b4141794265312f31586b56476473463255.acb8a942c0cb195c275de2d89b4c984479437f1f6d62a097650fb395087e8ae1")

(define legacy-bwk1-token
  "BWK1.2026a.3d3d777446656270514d637a49705634384c6c4e426a7a306f6d31314f6c6749434a464456574d2b7a78334965726c306e69364f65543745716e6d4d774947323348527536564e5844523777372b31586b56476473463255.5127137487dd307f4e0a4d69c06706983944369f0200166d500e0988f466982a")

(define (flip-hex-digit s index)
  "Return @var{s} with the character at @var{index} replaced by a different
   hexadecimal digit."
  (let* ((ch (string-ref s index))
         (replacement (if (char=? ch #\0) #\1 #\0)))
    (string-append (substring s 0 index)
                   (string replacement)
                   (substring s (+ index 1) (string-length s)))))

(define (argon2id-round-trip-works?)
  (let* ((generated (run-cli (list "token" "generate"
                                   "--owner-id" "owner-1"
                                   "--encryption-key" encryption-key
                                   "--signing-key" signing-key
                                   "--kdf" "argon2id"
                                   "--kdf-memory-kib" "8192"
                                   "--kdf-iterations" "1")))
         (token (string-trim-right (cli-out generated)))
         (decrypted (run-cli (list "token" "decrypt" "--token" token
                                   "--encryption-key" encryption-key
                                   "--signing-key" signing-key))))
    (and (= 0 (cli-code generated))
         (and (string-contains token "BWK3.") #t)
         (= 0 (cli-code decrypted))
         (and (string-contains (cli-out decrypted) "owner-1") #t))))

(define (kdf-parameter-without-name-rejected?)
  (= 1 (cli-code (run-cli (list "token" "generate"
                                "--owner-id" "owner-1"
                                "--encryption-key" encryption-key
                                "--signing-key" signing-key
                                "--kdf-memory-kib" "8192")))))

(define (legacy-token-refused? token)
  ;; Neither command may treat a dropped format as a session: decrypting must
  ;; fail even though these were sealed with the keys passed in, and inspect
  ;; must not print metadata for them.
  (and (= 1 (cli-code (run-cli (list "token" "decrypt" "--token" token
                                     "--encryption-key" encryption-key
                                     "--signing-key" signing-key))))
       (= 1 (cli-code (run-cli (list "token" "inspect" "--token" token))))))

(define (tampered-token-refused?)
  (let* ((generated (token-generate))
         (token (string-trim-right (cli-out generated)))
         (tampered (flip-hex-digit token
                                   (quotient (string-length token) 2))))
    (= 1 (cli-code (run-cli (list "token" "decrypt" "--token" tampered
                                  "--encryption-key" encryption-key
                                  "--signing-key" signing-key))))))

(define (missing-owner-id-refused?)
  (= 1 (cli-code (run-cli (list "token" "generate"
                                "--encryption-key" encryption-key
                                "--signing-key" signing-key)))))

(define (object-without-keys-refused?)
  (= 1 (cli-code (run-cli '("object" "encrypt")))))

(define format-policy-suite
  (suite "CLI key derivation and dropped formats"
         (test "the key derivation is chosen when sealing and read back when opening"
               (assert-true (argon2id-round-trip-works?)
                            #:name "an Argon2id token round-trips through the CLI")
               (assert-true (kdf-parameter-without-name-rejected?)
                            #:name "a KDF parameter without --kdf is refused"))
         (test "envelopes of dropped formats are refused"
               (assert-true (legacy-token-refused? legacy-bwk1-token)
                            #:name "a BWK1 token cannot be decrypted or inspected")
               (assert-true (legacy-token-refused? legacy-bwk2-token)
                            #:name "a BWK2 token cannot be decrypted or inspected")
               (assert-true (legacy-token-refused? "")
                            #:name "an empty token is refused"))
         (test "tampering and missing arguments are refused"
               (assert-true (tampered-token-refused?)
                            #:name "an edited token exits with 1")
               (assert-true (missing-owner-id-refused?)
                            #:name "generating without an owner id exits with 1")
               (assert-true (object-without-keys-refused?)
                            #:name "sealing an object without keys exits with 1"))
         (test "a refusal does not reveal which key ids the keyring configures"
               (assert-true (cli-key-id-refusals-are-uniform?)
                            #:name "an unknown key id and an edited body give the same message and exit code"))))

;; The hashing commands are the scripting surface for a deployment that wants
;; to store passwords without linking Guile: the hash goes to standard output,
;; the verdict is the exit code, and a failure says nothing beside a success.
(define (cli-hash password)
  (string-trim-right (cli-out (run-cli (list "password" "hash" password)))))

(define (cli-hash-verifies?)
  (= 0 (cli-code (run-cli (list "password" "verify" (cli-hash "correct horse battery staple")
                              "correct horse battery staple")))))

(define (cli-hash-rejects?)
  (= 1 (cli-code (run-cli (list "password" "verify" (cli-hash "correct horse battery staple")
                              "wrong password")))))

(define (cli-verify-failure-output)
  (car (run-cli-with-error
        (list "password" "verify" (cli-hash "correct horse battery staple")
              "wrong password"))))

(define password-hashing-suite
  (suite "CLI password hashing"
         (test "password hash and verify"
               (assert-true (password-hash? (cli-hash "correct horse battery staple"))
                            #:name "the command prints a PHC Argon2id hash")
               (assert-true (cli-hash-verifies?)
                            #:name "the same password verifies with exit code 0")
               (assert-true (cli-hash-rejects?)
                            #:name "a wrong password exits with 1")
               (assert-equal #:expect ""
                             #:got (cli-verify-failure-output)
                             #:name "a failed verification writes nothing to standard output")
               (assert-equal #:expect 1
                             #:got (cli-code (run-cli (list "password" "verify"
                                                             "not-a-hash" "x")))
                             #:name "a malformed hash exits with 1"))))


(define (cli-help-works?)
  (let ((result (run-cli (list "--help"))))
    (and (= 0 (cli-code result))
         (if (string-contains (cli-out result) "Usage:") #t #f))))

(define (argon2id-parallelism-round-trip?)
  (let* ((generated (run-cli (list "token" "generate" "--owner-id" "o1"
                                   "--encryption-key" encryption-key
                                   "--signing-key" signing-key
                                   "--kdf" "argon2id"
                                   "--kdf-memory-kib" "64"
                                   "--kdf-iterations" "1"
                                   "--kdf-parallelism" "2")))
         (token (string-trim-right (cli-out generated)))
         (decrypted (run-cli (list "token" "decrypt" "--token" token
                                   "--encryption-key" encryption-key
                                   "--signing-key" signing-key))))
    (and (= 0 (cli-code generated))
         (= 0 (cli-code decrypted))
         (if (string-contains (cli-out decrypted) "owner-id") #t #f))))

(define (env-keys-round-trip?)
  ;; The environment fallbacks are exercised in a child process, with `env'
  ;; supplying the variables to that process alone: setenv here would change
  ;; what every concurrently running test sees, which Guile documents as
  ;; unspecified once threads are running.
  (let* ((prefix (string-append "env BEWAKING_ENCRYPTION_KEY=" encryption-key
                                " BEWAKING_SIGNING_KEY=" signing-key))
         (generate (open-input-pipe
                    (string-append
                     prefix " guile -L ./src -c "
                     "'(exit ((@ (bewaking cli) run) "
                     "(list \"token\" \"generate\" \"--owner-id\" \"o1\")))'")))
         (token (string-trim-right (get-string-all generate)))
         (generate-status (close-pipe generate)))
    (and (zero? generate-status)
         (not (string-null? token))
         (let* ((decrypt (open-input-pipe
                          (string-append
                           prefix " guile -L ./src -c "
                           "'(exit ((@ (bewaking cli) run) "
                           "(list \"token\" \"decrypt\" \"--token\" \""
                           token "\")))'")))
                (output (get-string-all decrypt))
                (decrypt-status (close-pipe decrypt)))
           (and (zero? decrypt-status)
                (if (string-contains output "owner-id") #t #f))))))

(define cli-surface-suite
  (suite "CLI surface"
         (test "help, parallel Argon2id and environment keys"
               (assert-true (cli-help-works?)
                            #:name "--help prints the usage text and exits 0")
               (assert-true (argon2id-parallelism-round-trip?)
                            #:name "--kdf-parallelism seals and opens an Argon2id token")
               (assert-true (env-keys-round-trip?)
                            #:name "BEWAKING_ENCRYPTION_KEY and BEWAKING_SIGNING_KEY are picked up"))))

(define (spec)
  (veritas-run dispatch-suite token-suite object-suite password-suite
               rotation-metadata-suite format-policy-suite
               password-hashing-suite cli-surface-suite))
