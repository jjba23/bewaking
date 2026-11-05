;; bewaking
;;
;; SPDX-License-Identifier: MIT
;; Copyright © Josep Bigorra <jjbigorra@gmail.com>

(define-module (bewaking password)
  #:use-module (ice-9 format)
  #:use-module (srfi srfi-1)
  #:use-module (rnrs bytevectors)
  #:use-module (bewaking crypto)
  #:export (password-character-classes
            password-entropy
            password-strength
            password-strength-label
            strong-password?
            generate-strong-password
            hash-password
            verify-password
            password-hash?))

;; Generated passwords and password hashes draw from libgcrypt's CSPRNG through
;; `random-bytes', never from `*random-state*'. A password is a secret, and
;; `random' is not promised to be unpredictable; and reseeding the caller's
;; global state at import time changed the numbers every program that uses
;; `random' saw, merely by loading this module.

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

;; A character is a symbol when it is not a letter, a digit or whitespace:
;; punctuation, math symbols and other printable non-alphanumeric characters.

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
     ; => (lowercase uppercase digit symbol)

   The password is walked once, accumulating the four flags; the previous
   version scanned the whole password once per class, which made this the most
   expensive part of `password-strength` for long passphrases."
  (let loop ((index 0)
             (lowercase? #f) (uppercase? #f) (digit? #f) (symbol? #f))
    (if (= index (string-length password))
        (let ((present (list (cons 'lowercase lowercase?)
                             (cons 'uppercase uppercase?)
                             (cons 'digit digit?)
                             (cons 'symbol symbol?))))
          (map car (filter cdr present)))
        (let ((character (string-ref password index)))
          (cond ((char-set-contains? char-set:lower-case character)
                 (loop (+ index 1) #t uppercase? digit? symbol?))
                ((char-set-contains? char-set:upper-case character)
                 (loop (+ index 1) lowercase? #t digit? symbol?))
                ((char-set-contains? char-set:digit character)
                 (loop (+ index 1) lowercase? uppercase? #t symbol?))
                ((char-set-contains? char-set:whitespace character)
                 (loop (+ index 1) lowercase? uppercase? digit? symbol?))
                ((char-set-contains? char-set:letter character)
                 ;; A letter that is neither upper nor lower case (a CJK
                 ;; ideograph, for example) is a letter, not a symbol.
                 (loop (+ index 1) lowercase? uppercase? digit? symbol?))
                (else
                 (loop (+ index 1) lowercase? uppercase? digit? #t)))))))

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

(define (password-feedback password classes common? repeated-run sequential-run)
  "Build the list of actionable feedback strings for @var{password}.

   The two run lengths are passed in because `password-strength` has already
   measured them; recomputing them here made every strength check scan the
   password twice more than it needed to."
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
            (if (>= repeated-run 3)
                (list "Avoid repeating the same character three or more times in a row.")
                '())
            (if (>= sequential-run 4)
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
         (feedback (password-feedback password classes common?
                                      repeated-run sequential-run)))
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

(define (secure-random-integer bound)
  "Return an integer in [0, @var{bound}) drawn from libgcrypt's CSPRNG.

   Values above the largest multiple of @var{bound} are drawn again, so the
   result is uniform instead of folding the tail of the range back in — the
   modulo bias that makes a naive `(modulo random-byte bound)` weaker than the
   generator it draws from."
  (unless (and (integer? bound) (> bound 0) (<= bound 4294967296))
    (error
     "bewaking: the random bound must be an integer between 1 and 2^32."))
  (let ((limit (* (quotient 4294967296 bound) bound)))
    (let loop ()
      (let ((value (bytevector-uint-ref (random-bytes 4) 0 (endianness big) 4)))
        (if (< value limit)
            (modulo value bound)
            (loop))))))

(define (shuffle-list lst)
  "Return a new list containing the elements of @var{lst} in uniformly
   shuffled order (Fisher-Yates)."
  (let ((vec (list->vector lst)))
    (let loop ((i (- (vector-length vec) 1)))
      (if (< i 1)
          (vector->list vec)
          (let* ((j (secure-random-integer (+ i 1)))
                 (a (vector-ref vec i))
                 (b (vector-ref vec j)))
            (vector-set! vec i b)
            (vector-set! vec j a)
            (loop (- i 1)))))))

(define (random-char-from s)
  "Return a uniformly random character drawn from the string @var{s}."
  (string-ref s (secure-random-integer (string-length s))))

;; ====== Password hashing ======
;;
;; `password-strength` measures a password a user has chosen; `hash-password`
;; prepares one for storage, and `verify-password` checks a later attempt
;; against the stored value. The stored form is a PHC string, the encoding the
;; Argon2 authors specify, so the parameters travel with the hash: raising the
;; cost tomorrow does not invalidate anything stored today, because verification
;; derives with the parameters the hash itself records.

(define password-hash-prefix
  "$argon2id$v=19$")

(define password-hash-salt-length
  16)

(define password-hash-length
  32)

;; A verifier is usually handed a hash that came from somewhere untrusted, so
;; the cost it records is bounded before any memory is allocated or any pass is
;; run. The ceilings are far above the defaults and far below the point where a
;; single verification could exhaust the machine; a hash outside them is simply
;; not a hash this library will act on.
(define default-password-hash-max-memory-kib
  262144)

(define default-password-hash-max-iterations
  16)

(define (strip-base64-padding encoded)
  "Return @var{encoded} without its trailing padding characters."
  (let loop ((end (string-length encoded)))
    (if (and (> end 0) (char=? (string-ref encoded (- end 1)) #\=))
        (loop (- end 1))
        (substring encoded 0 end))))

(define (pad-base64 encoded)
  "Return @var{encoded} with the padding standard Base64 requires."
  (let ((remainder (modulo (string-length encoded) 4)))
    (if (zero? remainder)
        encoded
        (string-append encoded (make-string (- 4 remainder) #\=)))))

(define (decode-base64-or-#f value)
  "Decode @var{value} as Base64, returning #f when it is not Base64."
  (and (string? value)
       (not (string-null? value))
       (call-with-error-handler
        (lambda () (base64->bytes (pad-base64 value)))
        (lambda (key args) #f))))

(define (parse-phc-parameters field)
  "Parse a PHC parameter field such as @code{m=65536,t=3,p=1} into an alist of
   @code{m}, @code{t} and @code{p}, or #f when it is incomplete, repeated or
   malformed."
  (let loop ((parts (string-split field #\,)) (parameters '()))
    (if (null? parts)
        (let ((memory (assoc-ref parameters 'm))
              (iterations (assoc-ref parameters 't))
              (parallelism (assoc-ref parameters 'p)))
          (and memory iterations parallelism parameters))
        (let* ((part (car parts))
               (equals (string-contains part "=")))
          (if (not equals)
              #f
              (let ((name (string->symbol
                           (substring part 0 equals)))
                    (value (string->number
                            (substring part (+ equals 1)
                                       (string-length part)))))
                (if (and value
                         (integer? value)
                         (>= value 0)
                         (memq name '(m t p))
                         (not (assoc name parameters)))
                    (loop (cdr parts) (acons name value parameters))
                    #f)))))))

(define (parse-password-hash value)
  "Return an alist describing the Argon2id PHC string @var{value}, or #f when
   it is not one. The alist holds @code{memory-kib}, @code{iterations},
   @code{parallelism}, @code{salt} and @code{hash}."
  (and (string? value)
       (string-prefix? password-hash-prefix value)
       (let ((parts (string-split
                     (substring value (string-length password-hash-prefix)
                                (string-length value))
                     #\$)))
         (and (= (length parts) 3)
              (let ((parameters (parse-phc-parameters (list-ref parts 0)))
                    (salt (decode-base64-or-#f (list-ref parts 1)))
                    (hash (decode-base64-or-#f (list-ref parts 2))))
                (and parameters
                     salt
                     hash
                     (>= (bytevector-length salt) 8)
                     (>= (bytevector-length hash) 16)
                     (list (cons 'memory-kib (assoc-ref parameters 'm))
                           (cons 'iterations (assoc-ref parameters 't))
                           (cons 'parallelism (assoc-ref parameters 'p))
                           (cons 'salt salt)
                           (cons 'hash hash))))))))

(define (password-hash? value)
  "Return #t when @var{value} is a well-formed Argon2id PHC hash string, as
   produced by `hash-password`."
  (and (parse-password-hash value) #t))

(define* (hash-password #:key password
                        (memory-kib default-argon2id-memory-kib)
                        (iterations default-argon2id-iterations)
                        (parallelism default-argon2id-parallelism))
  "Hash @var{password} with Argon2id and return a PHC string such as
   @code{$argon2id$v=19$m=65536,t=3,p=1$...$...}.

   A fresh 16-byte salt is drawn from the CSPRNG for every call, so hashing the
   same password twice gives two different strings; the parameters are recorded
   in the string, so `verify-password` needs no configuration to check it later.

   #:key memory-kib:  Argon2id memory cost in kibibytes (default 65536).
   #:key iterations:  Argon2id passes (default 3).
   #:key parallelism: Argon2id lanes (default 1).

   #:example
     (hash-password #:password \"correct horse battery staple\")"
  (let* ((salt (random-bytes password-hash-salt-length))
         (hash (argon2id-derive password salt password-hash-length
                                #:memory-kib memory-kib
                                #:iterations iterations
                                #:parallelism parallelism)))
    (format #f "~am=~a,t=~a,p=~a$~a$~a"
            password-hash-prefix memory-kib iterations parallelism
            (strip-base64-padding (bytes->base64 salt))
            (strip-base64-padding (bytes->base64 hash)))))

(define* (verify-password #:key password hash
                          (max-memory-kib
                           default-password-hash-max-memory-kib)
                          (max-iterations
                           default-password-hash-max-iterations))
  "Return #t when @var{password} is the one @var{hash} was made from, and #f
   otherwise — including when @var{hash} is not a hash this library wrote.

   The recorded cost is refused, not obeyed, when it is beyond
   @var{max-memory-kib} or @var{max-iterations}: a hash normally arrives from
   storage or from a client, and a 4 GiB memory cost would be a denial of
   service rather than a credential. The comparison itself is constant-time.

   #:example
     (verify-password #:password attempt #:hash stored-hash)"
  (let ((parsed (parse-password-hash hash)))
    (and parsed
         (let ((memory-kib (assoc-ref parsed 'memory-kib))
               (iterations (assoc-ref parsed 'iterations))
               (salt (assoc-ref parsed 'salt))
               (expected (assoc-ref parsed 'hash)))
           (and (<= memory-kib max-memory-kib)
                (<= iterations max-iterations)
                (constant-time-equal?
                 (argon2id-derive password salt
                                  (bytevector-length expected)
                                  #:memory-kib memory-kib
                                  #:iterations iterations
                                  #:parallelism (assoc-ref parsed 'parallelism))
                 expected))))))

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
