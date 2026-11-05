;; bewaking
;;
;; SPDX-License-Identifier: MIT
;; Copyright © Josep Bigorra <jjbigorra@gmail.com>

(define-module (bewaking password)
  #:use-module (ice-9 format)
  #:use-module (srfi srfi-1)
  #:export (password-character-classes
            password-entropy
            password-strength
            password-strength-label
            strong-password?
            generate-strong-password))

;; Seed the random state from the platform so that generated passwords are
;; unpredictable across runs. Users may still `set!` *random-state* themselves;
;; this only establishes a sensible, non-deterministic default at import time.
(set! *random-state* (random-state-from-platform))

;; A compact list of very common passwords. Matching any of these caps the
;; strength score at zero, regardless of length or character variety.
(define common-passwords
  '("123456" "password" "12345678" "qwerty" "123456789" "12345" "1234"
    "111111" "1234567" "dragon" "123123" "baseball" "abc123" "football"
    "monkey" "letmein" "shadow" "master" "666666" "qwertyuiop" "123321"
    "mustang" "1234567890" "michael" "654321" "superman" "1qaz2wsx"
    "7777777" "121212" "000000" "iloveyou" "admin" "welcome" "login"
    "princess" "solo" "starwars" "passw0rd" "hello" "freedom" "whatever"))

;; Approximate number of distinct characters a password could draw from for
;; each detected class. These are used to estimate the search-space size.
(define class-pool-sizes
  '((lowercase . 26)
    (uppercase . 26)
    (digit . 10)
    (symbol . 33)))

;; Everything that is not a letter, digit or whitespace counts as a symbol:
;; punctuation, math symbols and other printable non-alphanumeric characters.
(define symbol-char-set
  (char-set-complement
   (char-set-union char-set:letter char-set:digit char-set:whitespace)))

(define (log2 x)
  "Return the base-2 logarithm of @var{x}."
  (/ (log x) (log 2)))

(define (list-size lst)
  "Return the number of elements in @var{lst}.

   A small alias around the core @code{length} procedure, so that functions with
   a keyword parameter named @code{length} can still measure lists."
  (length lst))

(define (password-character-classes password)
  "Return the list of character classes present in @var{password}.

   The returned symbols are drawn from: @code{lowercase}, @code{uppercase},
   @code{digit} and @code{symbol}. Anything that is not a letter, digit or
   whitespace is treated as a symbol, so punctuation, math symbols and other
   printable non-alphanumeric characters are covered.

   #:example
     (password-character-classes \"Abc123!\")
     ; => (lowercase uppercase digit symbol)"
  (map car
       (filter (lambda (entry)
                 (string-any (cdr entry) password))
               (list (cons 'lowercase char-set:lower-case)
                     (cons 'uppercase char-set:upper-case)
                     (cons 'digit char-set:digit)
                     (cons 'symbol symbol-char-set)))))

(define (password-pool-size classes)
  "Return the estimated size of the character pool described by @var{classes},
   the list of class symbols returned by `password-character-classes`."
  (let loop ((rest classes) (total 0))
    (if (null? rest)
        (max 1 total)
        (loop (cdr rest)
              (+ total (or (assoc-ref class-pool-sizes (car rest)) 0))))))

(define* (password-entropy #:key password)
  "Return the raw estimated entropy of @var{password} in bits.

   The estimate is @code{length * log2(pool-size)}, where the pool size is the
   sum of the sizes of every character class present in the password. This is a
   simple model of guessing difficulty, not a guarantee of strength; use
   `password-strength` for a penalty-adjusted score.

   #:example
     (password-entropy #:password \"Tr0ub4dor&3\") ; => a number of bits"
  (if (= 0 (string-length password))
      0
      (* (string-length password)
         (log2 (password-pool-size (password-character-classes password))))))

(define (longest-run password same?)
  "Return the length of the longest run of adjacent characters in @var{password}
   for which @var{same?} holds for consecutive pairs."
  (let ((chars (string->list password)))
    (if (< (length chars) 2)
        (length chars)
        (let loop ((rest (cdr chars)) (previous (car chars)) (current 1)
                   (longest 1))
          (if (null? rest)
              longest
              (let ((next (car rest)))
                (if (same? previous next)
                    (loop (cdr rest) next (+ current 1)
                          (max longest (+ current 1)))
                    (loop (cdr rest) next 1 longest))))))))

(define (sequential-run-length password)
  "Return the longest run of consecutively increasing or decreasing characters
   in @var{password} (for example \"abcd\" or \"4321\"). A run of two characters
   counts as two."
  (let ((chars (string->list password)))
    (if (< (length chars) 2)
        (length chars)
        (let loop ((rest (cdr chars)) (previous (car chars)) (current 1)
                   (longest 1))
          (if (null? rest)
              longest
              (let* ((next (car rest))
                     (delta (- (char->integer next)
                               (char->integer previous))))
                (if (or (= delta 1) (= delta -1))
                    (loop (cdr rest) next (+ current 1)
                          (max longest (+ current 1)))
                    (loop (cdr rest) next 1 longest))))))))

(define (password-strength-label score)
  "Return a human-readable label for a numeric strength @var{score} between
   0 and 4."
  (case score
    ((0) "very weak")
    ((1) "weak")
    ((2) "fair")
    ((3) "strong")
    ((4) "very strong")
    (else "unknown")))

(define (password-feedback password classes common?)
  "Build the list of actionable feedback strings for @var{password}."
  (let ((length (string-length password)))
    (append (if common?
                (list "This password appears in a list of commonly used passwords.")
                '())
            (if (< length 8)
                (list "Use at least 8 characters; 12 or more is better.")
                '())
            (if (< length 12)
                (list "Longer passphrases are significantly harder to crack.")
                '())
            (if (not (memq 'lowercase classes))
                (list "Add lowercase letters.")
                '())
            (if (not (memq 'uppercase classes))
                (list "Add uppercase letters.")
                '())
            (if (not (memq 'digit classes))
                (list "Add digits.")
                '())
            (if (not (memq 'symbol classes))
                (list "Add symbols such as !, @ or #.")
                '())
            (if (>= (longest-run password char=?) 3)
                (list "Avoid repeating the same character three or more times in a row.")
                '())
            (if (>= (sequential-run-length password) 4)
                (list "Avoid sequences such as \"abcd\" or \"1234\".")
                '()))))

(define* (password-strength #:key password)
  "Measure the strength of @var{password} and return an association list
   describing the result.

   The estimate starts from `password-entropy`, then applies penalties for
   common passwords, short lengths, repeated characters and sequential runs.
   A common password always scores 0.

   The returned alist contains:
   - @code{score}:      integer 0 (very weak) to 4 (very strong)
   - @code{label}:      human-readable label for the score
   - @code{entropy}:    penalty-adjusted entropy estimate, in bits
   - @code{raw-entropy}: unpenalized entropy estimate, in bits
   - @code{length}:     length of the password
   - @code{classes}:    character classes detected (list of symbols)
   - @code{feedback}:   list of suggestions to improve the password

   #:example
     (password-strength #:password \"correct horse battery staple\")"
  (let* ((length (string-length password))
         (classes (password-character-classes password))
         (raw-entropy (password-entropy #:password password))
         (common? (and (member (string-downcase password) common-passwords)
                       #t))
         (repeated-run (longest-run password char=?))
         (sequential-run (sequential-run-length password))
         (penalty (+ (if common? raw-entropy 0)
                     (* 4 (max 0 (- repeated-run 2)))
                     (* 4 (max 0 (- sequential-run 2)))
                     (if (< length 8) 6 0)))
         (entropy (max 0 (- raw-entropy penalty)))
         (score (cond ((or common? (< length 1)) 0)
                      ((< entropy 28) 0)
                      ((< entropy 40) 1)
                      ((< entropy 60) 2)
                      ((< entropy 80) 3)
                      (else 4)))
         (feedback (password-feedback password classes common?)))
    `((score . ,score)
      (label . ,(password-strength-label score))
      (entropy . ,(exact->inexact (/ (round (* entropy 100)) 100)))
      (raw-entropy . ,(exact->inexact (/ (round (* raw-entropy 100)) 100)))
      (length . ,length)
      (classes . ,classes)
      (feedback . ,feedback))))

(define* (strong-password? #:key password (min-score 3))
  "Return #t when @var{password} scores at least @var{min-score} (default 3,
   \"strong\") according to `password-strength`, otherwise #f.

   #:example
     (strong-password? #:password \"Tr0ub4dor&3\") ; => #t or #f
     (strong-password? #:password \"123456\" #:min-score 4) ; => #f"
  (>= (assoc-ref (password-strength #:password password) 'score)
      min-score))

(define (shuffle-list lst)
  "Return a new list containing the elements of @var{lst} in uniformly
   shuffled order (Fisher-Yates)."
  (let ((vec (list->vector lst)))
    (let loop ((i (- (vector-length vec) 1)))
      (if (< i 1)
          (vector->list vec)
          (let* ((j (random (+ i 1)))
                 (a (vector-ref vec i))
                 (b (vector-ref vec j)))
            (vector-set! vec i b)
            (vector-set! vec j a)
            (loop (- i 1)))))))

(define (random-char-from s)
  "Return a uniformly random character drawn from the string @var{s}."
  (string-ref s (random (string-length s))))

(define* (generate-strong-password #:key (length 24) (include-symbols #t))
  "Generate a random password designed to be strong.

   One character from each included class is guaranteed, the remainder is drawn
   from the full pool, and the result is shuffled so no positional bias remains.

   #:key length:             total password length (default 24). Must be at least
                            as large as the number of included character classes.
   #:key include-symbols:    when #t (default) symbols are part of the pool.
   #:returns: a freshly generated password string.

   #:example
     (generate-strong-password)                       ; 24 chars, mixed classes
     (generate-strong-password #:length 32)
     (generate-strong-password #:length 16 #:include-symbols #f)"
  (let* ((classes (if include-symbols
                      (list "abcdefghijklmnopqrstuvwxyz"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "0123456789"
                            "!@#$%^&*()-_=+[]{};:,.?/")
                      (list "abcdefghijklmnopqrstuvwxyz"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "0123456789")))
         (pool (apply string-append classes)))
    (when (< length (list-size classes))
      (error
       (format #f "generate-strong-password: length must be at least ~a to cover every character class."
               (list-size classes))))
    (let* ((mandatory (map random-char-from classes))
           (remaining (- length (list-size mandatory)))
           (filler (let loop ((n remaining) (acc '()))
                     (if (= n 0)
                         acc
                         (loop (- n 1)
                               (cons (random-char-from pool) acc)))))
           (password (list->string (shuffle-list (append mandatory filler)))))
      password)))
