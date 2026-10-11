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

(define-module (veritas unit cli-spec)
  #:use-module (veritas veritas)
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

(define (spec)
  (veritas-run dispatch-suite token-suite object-suite password-suite
               rotation-metadata-suite))
