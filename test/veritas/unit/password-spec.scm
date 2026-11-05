;; bewaking
;;
;; SPDX-License-Identifier: MIT
;; Copyright © Josep Bigorra <jjbigorra@gmail.com>

(define-module (veritas unit password-spec)
  #:use-module (veritas veritas)
  #:use-module (bewaking password))

(define character-class-suite
  (suite "Password character classes"
         (test "password-character-classes"
               (assert-equal #:expect '(lowercase)
                             #:got (password-character-classes "abc")
                             #:name "lowercase letters only")
               (assert-equal #:expect '(uppercase)
                             #:got (password-character-classes "ABC")
                             #:name "uppercase letters only")
               (assert-equal #:expect '(digit)
                             #:got (password-character-classes "0123")
                             #:name "digits only")
               (assert-equal #:expect '(lowercase uppercase digit symbol)
                             #:got (password-character-classes "Abc123!")
                             #:name "all four classes are detected")
               (assert-equal #:expect '()
                             #:got (password-character-classes "")
                             #:name "an empty password has no classes"))))

(define entropy-suite
  (suite "Password entropy"
         (test "password-entropy"
               (assert-equal #:expect 0
                             #:got (password-entropy #:password "")
                             #:name "an empty password has zero entropy")
               (assert-true (and (> (password-entropy #:password "abcdefgh") 37)
                                 (< (password-entropy #:password "abcdefgh") 38))
                            #:name "eight lowercase letters are ~37.6 bits")
               (assert-true (> (password-entropy #:password "Abcdefgh")
                               (password-entropy #:password "abcdefgh"))
                            #:name "adding a character class increases the entropy"))))

(define strength-suite
  (suite "Password strength"
         (test "password-strength"
               (let ((common (password-strength #:password "123456"))
                     (weak (password-strength #:password "abc"))
                     (strong (password-strength #:password
                                                "correct horse battery staple"))
                     (empty (password-strength #:password "")))
                 (assert-equal #:expect 0
                               #:got (assoc-ref common 'score)
                               #:name "a common numeric password scores 0")
                 (assert-equal #:expect "very weak"
                               #:got (assoc-ref common 'label)
                               #:name "score 0 is labelled very weak")
                 (assert-equal #:expect 0
                               #:got (assoc-ref weak 'score)
                               #:name "a very short password scores 0")
                 (assert-equal #:expect 4
                               #:got (assoc-ref strong 'score)
                               #:name "a long passphrase scores 4")
                 (assert-equal #:expect "very strong"
                               #:got (assoc-ref strong 'label)
                               #:name "score 4 is labelled very strong")
                 (assert-equal #:expect 0
                               #:got (assoc-ref empty 'score)
                               #:name "an empty password scores 0")
                 (assert-true (> (assoc-ref strong 'entropy)
                                 (assoc-ref weak 'entropy))
                              #:name "stronger passwords have higher entropy")
                 (assert-true (list? (assoc-ref common 'feedback))
                              #:name "feedback is returned as a list")
                 (assert-true (and (member
                                    "This password appears in a list of commonly used passwords."
                                    (assoc-ref common 'feedback))
                                   #t)
                              #:name "common passwords get a specific warning"))
               (assert-true (and (member "Avoid sequences such as \"abcd\" or \"1234\"."
                                         (assoc-ref (password-strength #:password
                                                                       "abcdefgh")
                                                    'feedback))
                                 #t)
                            #:name "sequential runs are flagged in the feedback"))
         (test "strong-password?"
               (assert-false (strong-password? #:password "password")
                             #:name "a common word is not strong")
               (assert-false (strong-password? #:password "abc123")
                             #:name "a short mixed password is not strong")
               (assert-true (strong-password? #:password
                                              "correct horse battery staple")
                            #:name "a long passphrase is strong")
               (assert-true (strong-password? #:password "abc123"
                                              #:min-score 0)
                            #:name "min-score lowers the bar"))))

(define generator-suite
  (suite "Password generation"
         (test "generate-strong-password"
               (let ((generated (generate-strong-password)))
                 (assert-equal #:expect 24
                               #:got (string-length generated)
                               #:name "default length is 24")
                 (assert-true (strong-password? #:password generated)
                              #:name "a generated password is strong")
                 (assert-equal #:expect '(lowercase uppercase digit symbol)
                               #:got (password-character-classes generated)
                               #:name "default generated passwords use every class"))
               (assert-equal #:expect 32
                             #:got (string-length (generate-strong-password
                                                   #:length 32))
                             #:name "length is respected")
               (assert-equal #:expect '(lowercase uppercase digit)
                             #:got (password-character-classes
                                    (generate-strong-password
                                     #:length 16 #:include-symbols #f))
                             #:name "symbols can be excluded")
               (assert-error (lambda ()
                               (generate-strong-password #:length 2))
                             #:name "too-short a request raises an error"))))

;; Hashing is tested with the cheapest usable Argon2id parameters (8 KiB, one
;; pass, one lane) so the suite stays fast; the production defaults are 64 MiB
;; and three passes, which the library tests elsewhere through `kdf-spec'.
(define (fast-hash password)
  (hash-password #:password password #:memory-kib 8 #:iterations 1
                 #:parallelism 1))

(define (hashing-roundtrip?)
  (verify-password #:password "correct horse battery staple"
                   #:hash (fast-hash "correct horse battery staple")))

(define (wrong-password-verifies?)
  (verify-password #:password "wrong"
                   #:hash (fast-hash "correct horse battery staple")))

(define (memory-ceiling-refuses?)
  ;; The hash records 64 KiB; the verifier is told not to trust anything above
  ;; 8 KiB, so it must answer #f without deriving — the password is right, so a
  ;; #f here can only come from the cost bound.
  (verify-password #:password "same"
                   #:hash (hash-password #:password "same" #:memory-kib 64
                                         #:iterations 1 #:parallelism 1)
                   #:max-memory-kib 8))

(define (iteration-ceiling-refuses?)
  (verify-password #:password "same"
                   #:hash (fast-hash "same")
                   #:max-iterations 0))

(define hashing-suite
  (suite "Password hashing"
         (test "hash-password and verify-password"
               (assert-true (password-hash? (fast-hash "correct horse battery staple"))
                            #:name "a hash is a well-formed PHC Argon2id string")
               (assert-true (string-prefix? "$argon2id$v=19$m=8,t=1,p=1$"
                                            (fast-hash "x"))
                            #:name "the requested parameters are the ones recorded")
               (assert-true (hashing-roundtrip?)
                            #:name "the right password verifies")
               (assert-false (wrong-password-verifies?)
                             #:name "a wrong password does not verify")
               (assert-false (password-hash? "not a hash")
                             #:name "plain text is not a password hash")
               (assert-false (verify-password #:password "x" #:hash "not a hash")
                             #:name "a malformed hash verifies nothing")
               (assert-false (password-hash? "")
                             #:name "the empty string is not a password hash"))
         (test "salts and cost ceilings"
               (assert-false (string=? (fast-hash "same") (fast-hash "same"))
                             #:name "two hashes of one password differ, so each carries a fresh salt")
               (assert-false (memory-ceiling-refuses?)
                             #:name "a recorded memory cost above the ceiling is refused")
               (assert-false (iteration-ceiling-refuses?)
                             #:name "a recorded pass count above the ceiling is refused"))))


(define label-suite
  (suite "Strength labels"
         (test "password-strength-label"
               (assert-equal #:expect "very weak"
                             #:got (password-strength-label 0))
               (assert-equal #:expect "weak"
                             #:got (password-strength-label 1))
               (assert-equal #:expect "fair"
                             #:got (password-strength-label 2))
               (assert-equal #:expect "strong"
                             #:got (password-strength-label 3))
               (assert-equal #:expect "very strong"
                             #:got (password-strength-label 4))
               (assert-equal #:expect "unknown"
                             #:got (password-strength-label 9)
                             #:name "a score outside 0-4 is labelled unknown"))))

(define (spec)
  (veritas-run character-class-suite entropy-suite strength-suite
               generator-suite hashing-suite label-suite))
