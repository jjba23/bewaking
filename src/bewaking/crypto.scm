;; bewaking
;;
;; SPDX-License-Identifier: MIT
;; Copyright © Josep Bigorra <jjbigorra@gmail.com>

(define-module (bewaking crypto)
  #:use-module (ice-9 format)
  #:use-module (rnrs bytevectors)
  #:use-module (system foreign)
  #:use-module (srfi srfi-11)
  #:use-module (gcrypt mac)
  #:use-module (gcrypt package-config)
  #:use-module (gcrypt random)
  #:export (bytes->base16
            bytes->base64
            base64->bytes
            base16-encode
            base16-decode
            base64-encode
            base64-decode
            hmac-sha256-hex
            pbkdf2-sha256
            argon2id-derive
            argon2id-available?
            random-bytes
            base16->bytes
            kdf-spec
            kdf-name
            default-kdf
            default-argon2id-kdf
            derive-key-material
            kdf-encrypt
            kdf-decrypt
            gcm-encrypt
            gcm-decrypt
            openssl-encrypt
            openssl-decrypt
            gcm-salt-length
            gcm-nonce-length
            kdf-salt-length
            default-argon2id-memory-kib
            default-argon2id-iterations
            default-argon2id-parallelism
            constant-time-equal?
            call-with-error-handler
            condition-message))

;; ====== Overview ======
;;
;; This module implements, in Guile and inside this process, everything bewaking
;; used to shell out for:
;;
;;   - Base16 (hexadecimal) and Base64 encoding, which were done with `xxd' and
;;     `base64';
;;   - HMAC-SHA256, which was done with `openssl dgst';
;;   - AES-256-CBC with a PBKDF2-HMAC-SHA256 key derivation, which was done with
;;     `openssl enc -aes256 -pbkdf2'.
;;
;; No subprocess is spawned, nothing is interpolated into a shell, and payloads
;; are never passed through a command line (which could not carry NUL bytes
;; anyway).
;;
;; The AES, PBKDF2 and Argon2id primitives come from libgcrypt, the library
;; Guile already links against through guile-gcrypt, but which publishes no
;; Scheme bindings for ciphers or key derivation; they are bound here with
;; (system foreign). The encodings are plain Scheme.

;; ====== libgcrypt bindings ======

(define libgcrypt
  (dynamic-link %libgcrypt))

(define (libgcrypt-function name)
  "Return the libgcrypt symbol called @var{name}."
  (dynamic-func name libgcrypt))

(define (libgcrypt-procedure return-type name argument-types)
  "Return the libgcrypt function @var{name} as a Scheme procedure taking
   @var{argument-types} and returning @var{return-type}."
  (pointer->procedure return-type (libgcrypt-function name) argument-types))

(define (libgcrypt-procedure-or-#f return-type name argument-types)
  "Like `libgcrypt-procedure', but return #f when this libgcrypt has no such
   function, so that newer entry points can be used when available and reported
   as missing when not."
  (let ((function (catch #t
                           (lambda () (dynamic-func name libgcrypt))
                           (lambda (key . args) #f))))
    (and function (pointer->procedure return-type function argument-types))))

;; libgcrypt writes the handle it opens through a pointer to a `void *'. That
;; cell has to keep its address and its contents for as long as the handle is
;; open. Garbage-collected storage cannot promise that: once a cell is
;; reclaimed, the next call can allocate the same bytes, write its own handle
;; there, and then two open handles share one context. One of them closes the
;; other's handle, and libgcrypt reports either an unknown algorithm or a
;; closed handle. The cell therefore comes from malloc and is released with
;; free after the handle is closed.
(define libc
  (dynamic-link))

(define (libc-procedure return-type name argument-types)
  "Return the C library function @var{name} as a Scheme procedure taking
   @var{argument-types} and returning @var{return-type}."
  (pointer->procedure return-type (dynamic-func name libc) argument-types))

(define allocate-handle-cell
  (libc-procedure '* "malloc" (list size_t)))

(define release-handle-cell
  (libc-procedure void "free" (list '*)))

(define (take-handle-cell)
  "Return a pointer-sized cell libgcrypt can write a handle into. Release the
   cell with `release-handle-cell' once the handle it holds is closed."
  (allocate-handle-cell (sizeof '*)))

;; Algorithm and mode identifiers from <gcrypt.h>.
(define gcry-cipher-aes256 9)
(define gcry-cipher-mode-cbc 3)
(define gcry-cipher-mode-gcm 9)
;; GCRYCTL_FINALIZE, the command `gcry_cipher_final' is a macro for. Only the
;; documented recipes for GCM use it, so it is called explicitly for that mode.
(define gcry-ctl-finalize 5)
(define gcry-kdf-pbkdf2 34)
(define gcry-kdf-argon2 64)
(define gcry-kdf-argon2id 2)
(define gcry-md-sha256 8)

;; Parameters of the wire format produced by
;; `openssl enc -aes256 -pbkdf2 -a -A -k KEY'. OpenSSL stores an 8-byte salt in
;; a `Salted__' header, derives 32 key bytes and a 16-byte IV with
;; PBKDF2-HMAC-SHA256 over 10000 iterations, and encrypts the padded plaintext
;; with AES-256-CBC.
(define salt-length 8)
(define key-length 32)
(define iv-length 16)
(define block-length 16)
(define pbkdf2-iterations 10000)
(define openssl-header "Salted__")

(define gcry-kdf-derive
  (libgcrypt-procedure int "gcry_kdf_derive"
                       (list '* size_t int int '* size_t unsigned-long
                             size_t '*)))

(define gcry-cipher-open
  (libgcrypt-procedure int "gcry_cipher_open"
                       (list '* int int unsigned-int)))

(define gcry-cipher-setkey
  (libgcrypt-procedure int "gcry_cipher_setkey" (list '* '* size_t)))

(define gcry-cipher-setiv
  (libgcrypt-procedure int "gcry_cipher_setiv" (list '* '* size_t)))

(define gcry-cipher-encrypt
  (libgcrypt-procedure int "gcry_cipher_encrypt"
                       (list '* '* size_t '* size_t)))

(define gcry-cipher-decrypt
  (libgcrypt-procedure int "gcry_cipher_decrypt"
                       (list '* '* size_t '* size_t)))

(define gcry-cipher-close
  (libgcrypt-procedure void "gcry_cipher_close" (list '*)))

;; The AEAD entry points of the same cipher API: associated data in, tag out,
;; and a tag check that fails with GPG_ERR_CHECKSUM when the data or the
;; associated data was altered. `gcry_cipher_ctl' is the real function behind
;; the `gcry_cipher_final' macro, which GCM needs before the tag is read.
(define gcry-cipher-ctl
  (libgcrypt-procedure int "gcry_cipher_ctl" (list '* int '* size_t)))

(define gcry-cipher-authenticate
  (libgcrypt-procedure int "gcry_cipher_authenticate" (list '* '* size_t)))

(define gcry-cipher-gettag
  (libgcrypt-procedure int "gcry_cipher_gettag" (list '* '* size_t)))

(define gcry-cipher-checktag
  (libgcrypt-procedure int "gcry_cipher_checktag" (list '* '* size_t)))

;; Argon2 arrived in libgcrypt 1.11. It is *not* reachable through
;; gcry_kdf_derive, whose switch only dispatches to PBKDF2 and scrypt: the
;; stateful gcry_kdf_open / gcry_kdf_compute / gcry_kdf_final API is the one
;; that takes Argon2's memory, time and lane parameters. These bindings are
;; therefore resolved optionally: on an older libgcrypt they are #f and asking
;; for Argon2id reports that clearly instead of misbehaving.
(define gcry-kdf-open
  (libgcrypt-procedure-or-#f int "gcry_kdf_open"
                             (list '* int int '* unsigned-int '* size_t '*
                                   size_t '* size_t '* size_t)))

(define gcry-kdf-compute
  (libgcrypt-procedure-or-#f int "gcry_kdf_compute" (list '* '*)))

(define gcry-kdf-final
  (libgcrypt-procedure-or-#f int "gcry_kdf_final" (list '* size_t '*)))

(define gcry-kdf-close
  (libgcrypt-procedure-or-#f void "gcry_kdf_close" (list '*)))

(define gcry-strerror
  (libgcrypt-procedure '* "gcry_strerror" (list int)))

(define (call-with-error-handler thunk handler)
  "Call @var{thunk}, passing an ordinary error to @var{handler} as a
   @var{key} and @var{args} list.

   An asynchronous interrupt is not an ordinary error: a SIGINT arrives as
   ~(throw 'signal ...)~, and a ~(quit)~ or ~(exit)~ as ~'quit~. Those are
   rethrown untouched, so wrapping a long derivation in this helper does not
   make Ctrl-C stop working. Everything else — what ~error~ raises — is handed
   to @var{handler}, which is why the safe ~decrypt-token~-style wrappers can
   turn any failure into a value without swallowing the operator's interrupt."
  (catch #t
         thunk
         (lambda (key . args)
           (if (memq key '(signal quit))
               (apply throw key args)
               (handler key args)))))

(define (condition-message key args)
  "Best-effort human-readable text for an exception caught as @var{key} with
   @var{args}, for diagnostics that a person has to read.

   Guile reports an ~error~ through a formatting list whose leading element is
   the report port, and versions differ on whether that list arrives flat in
   @var{args} or nested inside it, so both shapes are accepted. Falls back to a
   plain string argument, then to the exception key, so a diagnostic is never
   lost."
  (define (first-string rest)
    (cond ((null? rest) #f)
          ((string? (car rest)) (car rest))
          (else (first-string (cdr rest)))))
  (define (formatting-data)
    (cond ((and (pair? args) (string? (car args))) args)
          ((and (pair? args) (eq? #f (car args))
                (pair? (cdr args)) (string? (cadr args)))
           (cdr args))
          (else
           (let loop ((rest args))
             (cond ((null? rest) #f)
                   ((and (pair? (car rest)) (string? (caar rest)))
                    (car rest))
                   (else (loop (cdr rest))))))))
  (let ((data (formatting-data)))
    (if data
        (call-with-error-handler
         (lambda ()
           (let ((template (car data)))
             (if (and (pair? (cdr data)) (list? (cadr data)))
                 (apply format #f template (cadr data))
                 (apply format #f data))))
         (lambda (key args) (first-string data)))
        (or (first-string args)
            (format #f "~a" key)))))

(define (check-libgcrypt error-code what)
  "Raise an error unless @var{error-code} reports success, describing @var{what}
   and libgcrypt's own message for the failure."
  (unless (= error-code 0)
    (error (format #f "bewaking: ~a failed: ~a"
                   what
                   (pointer->string (gcry-strerror error-code))))))

(define (call-with-libgcrypt-handle what open close body)
  "Open a libgcrypt handle and call @var{body} with it.

   @var{open} is called with the cell libgcrypt writes the handle into and
   returns libgcrypt's error code; @var{what} names the call in the error
   raised when it fails. @var{close} closes the handle, and may be #f when the
   loaded libgcrypt lacks that function.

   The handle is closed, and the cell released, exactly once: when @var{body}
   returns, and when it raises. `dynamic-wind' is the obvious way to spell
   that and is the wrong one here, because its winders run every time the
   fiber is suspended and its before thunks every time it is resumed. Under
   Fibers -- which bewaking's own test runner uses, and which any application
   that bounds work with a timeout also ends up inside -- a suspension inside
   @var{body} therefore closes the handle, and the rest of @var{body} goes on
   using a freed one. That reads as a crash, or as libgcrypt reporting an
   unknown algorithm for a handle it has already destroyed. The suspension
   need not be @var{body}'s own doing: an interrupted async, or a timeout
   watchdog marking the kernel thread, lands on the safe point at the end of
   a long libgcrypt call, which is enough. A `catch' around the body has none
   of that behaviour: it runs on the two exits that matter, and on nothing
   else.

   Abandoning a fiber mid-call is not one of those exits, so the handle and
   its cell leak; that is the price of not being able to tell a suspension
   from an exit, and it is bounded by one handle per abandoned call."
  (let ((cell (take-handle-cell)))
    (let ((error-code (open cell)))
      (unless (zero? error-code)
        (release-handle-cell cell)
        (check-libgcrypt error-code what)))
    (let ((handle (dereference-pointer cell))
          (closed? #f))
      (define (close!)
        (unless closed?
          (set! closed? #t)
          (when close (close handle))
          (release-handle-cell cell)))
      (catch #t
             (lambda ()
               (let ((result (body handle)))
                 (close!)
                 result))
             (lambda (key . args)
               (close!)
               (apply throw key args))))))

;; ====== Randomness ======

(define (bytevector-slice bytes start end)
  "Return a fresh bytevector holding the bytes of @var{bytes} from @var{start}
   up to (but not including) @var{end}."
  (let ((out (make-bytevector (- end start) 0)))
    (bytevector-copy! bytes start out 0 (- end start))
    out))

(define (bytes-concatenate . parts)
  "Return a fresh bytevector holding @var{parts} one after another."
  (let ((out (make-bytevector (apply + (map bytevector-length parts)) 0)))
    (let loop ((parts parts) (offset 0))
      (if (null? parts)
          out
          (let ((part (car parts)))
            (bytevector-copy! part 0 out offset (bytevector-length part))
            (loop (cdr parts) (+ offset (bytevector-length part))))))))

(define* (random-bytes #:optional (length salt-length))
  "Return a bytevector of @var{length} cryptographically strong random bytes."
  (gen-random-bv length))

;; ====== Base16 (hexadecimal) ======

;; Two 256-entry vectors of characters, one per nibble. A byte then costs two
;; `vector-ref's and two `string-set!'s, with no per-byte string allocation and
;; no second lookup into a two-character string; the `format'-built table this
;; replaces spent most of its time in `format' once per byte of output.
(define hex-high-digits
  (let ((table (make-vector 256 #\0)))
    (do ((i 0 (+ i 1))) ((= i 256) table)
      (vector-set! table i (string-ref "0123456789abcdef" (quotient i 16))))))

(define hex-low-digits
  (let ((table (make-vector 256 #\0)))
    (do ((i 0 (+ i 1))) ((= i 256) table)
      (vector-set! table i (string-ref "0123456789abcdef" (modulo i 16))))))

(define (bytes->base16 bytes)
  "Return the lowercase hexadecimal encoding of @var{bytes}, one byte per two
   digits."
  (let* ((length (bytevector-length bytes))
         (out (make-string (* 2 length) #\0)))
    (do ((i 0 (+ i 1))) ((= i length) out)
      (let ((byte (bytevector-u8-ref bytes i)))
        (string-set! out (* 2 i) (vector-ref hex-high-digits byte))
        (string-set! out (+ (* 2 i) 1) (vector-ref hex-low-digits byte))))))

(define (base16-encode value)
  "Return the lowercase hexadecimal encoding of the string @var{value}, one
   byte per two digits."
  (bytes->base16 (string->utf8 value)))

;; One 256-entry table from character code to digit value, built once instead of
;; the four range tests the comparison chain used to run for every digit.
(define hex-values
  (let ((table (make-vector 256 #f)))
    (do ((i 0 (+ i 1))) ((= i 10) table)
      (vector-set! table (+ 48 i) i))
    (do ((i 0 (+ i 1))) ((= i 6) table)
      (vector-set! table (+ 97 i) (+ 10 i))
      (vector-set! table (+ 65 i) (+ 10 i)))
    table))

(define (hex-digit-value character)
  "Return the value of the hexadecimal digit @var{character}, accepting both
   cases, or #f when it is not a hexadecimal digit."
  (let ((code (char->integer character)))
    (and (< code 256) (vector-ref hex-values code))))

(define (base16->bytes value)
  "Decode the hexadecimal string @var{value} into a bytevector. Upper and lower
   case digits are both accepted. Raises an error when the input has an odd
   number of digits or contains a non-hexadecimal character.

   Unlike `base16-decode` this returns the raw bytes, so it can read hexadecimal
   that stands for binary data rather than for text."
  (unless (string? value)
    (error "bewaking: base16->bytes expects a string."))
  (let ((digits (string-length value)))
    (when (odd? digits)
      (error "bewaking: malformed hexadecimal input (odd number of digits)."))
    (let* ((length (quotient digits 2))
           (bytes (make-bytevector length 0)))
      (do ((i 0 (+ i 1))) ((= i length))
        (let ((high (hex-digit-value (string-ref value (* 2 i))))
              (low (hex-digit-value (string-ref value (+ (* 2 i) 1)))))
          (unless (and high low)
            (error "bewaking: malformed hexadecimal input."))
          (bytevector-u8-set! bytes i (+ (* 16 high) low))))
      bytes)))

(define (base16-decode value)
  "Decode the hexadecimal string @var{value} into a string. Upper and lower
   case digits are both accepted. Raises an error when the input has an odd
   number of digits or contains a non-hexadecimal character."
  (utf8->string (base16->bytes value)))

;; ====== Base64 ======

(define base64-alphabet
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

(define base64-values
  (let ((table (make-vector 256 #f)))
    (do ((i 0 (+ i 1))) ((= i 64) table)
      (vector-set! table (char->integer (string-ref base64-alphabet i)) i))))

(define base64-characters
  ;; The Base64 alphabet as a vector of characters, so encoding is a
  ;; `vector-ref' rather than a `string-ref' into a literal string per byte.
  (let ((table (make-vector 64 #\A)))
    (do ((i 0 (+ i 1))) ((= i 64) table)
      (vector-set! table i (string-ref base64-alphabet i)))))

(define (bytes->base64 bytes)
  "Return the standard, padded, single-line Base64 encoding of @var{bytes}."
  (let* ((length (bytevector-length bytes))
         (full (quotient length 3))
         (rest (modulo length 3))
         (out (make-string (* 4 (+ full (if (zero? rest) 0 1))) #\=)))
    (do ((i 0 (+ i 1))) ((= i full))
      (let ((triple (+ (* 65536 (bytevector-u8-ref bytes (* 3 i)))
                       (* 256 (bytevector-u8-ref bytes (+ (* 3 i) 1)))
                       (bytevector-u8-ref bytes (+ (* 3 i) 2)))))
        (do ((j 0 (+ j 1))) ((= j 4))
          (string-set! out (+ (* 4 i) j)
                       (vector-ref base64-characters
                                   (logand (ash triple (- (* 6 (- 3 j))))
                                           63))))))
    (unless (zero? rest)
      (let* ((base (* 4 full))
             (a (bytevector-u8-ref bytes (* 3 full)))
             (b (if (= rest 2) (bytevector-u8-ref bytes (+ (* 3 full) 1)) 0))
             (triple (+ (* 65536 a) (* 256 b))))
        (string-set! out base
                     (vector-ref base64-characters
                                 (logand (ash triple -18) 63)))
        (string-set! out (+ base 1)
                     (vector-ref base64-characters
                                 (logand (ash triple -12) 63)))
        (when (= rest 2)
          (string-set! out (+ base 2)
                       (vector-ref base64-characters
                                   (logand (ash triple -6) 63))))))
    out))

(define (base64->bytes value)
  "Decode the Base64 string @var{value} into a bytevector. Whitespace is
   ignored, up to two trailing padding characters are accepted, and anything
   else raises an error."
  (unless (string? value)
    (error "bewaking: base64-decode expects a string."))
  (let* ((length (string-length value))
         (symbols (make-vector (+ length 4) 0))
         (padding 0)
         (saw-padding? #f)
         (count 0))
    (do ((i 0 (+ i 1))) ((= i length))
      (let ((character (string-ref value i)))
        (cond ((char-set-contains? char-set:whitespace character))
              ((char=? character #\=)
               (set! saw-padding? #t)
               (set! padding (+ padding 1)))
              (saw-padding?
               (error "bewaking: malformed base64 input (data after padding)."))
              (else
               (let ((six (vector-ref base64-values (char->integer character))))
                 (unless six
                   (error "bewaking: malformed base64 input."))
                 (vector-set! symbols count six)
                 (set! count (+ count 1)))))))
    (let ((tail (modulo count 4)))
      (unless (and (= 0 (modulo (+ count padding) 4))
                   (or (= padding 0) (= padding 1) (= padding 2))
                   (or (and (= padding 0) (= tail 0))
                       (and (= padding 1) (= tail 3))
                       (and (= padding 2) (= tail 2))))
        (error "bewaking: malformed base64 input (bad length or padding).")))
    (let* ((groups (quotient count 4))
           (tail (modulo count 4))
           (length (+ (* groups 3)
                      (cond ((= tail 3) 2)
                            ((= tail 2) 1)
                            (else 0))))
           (bytes (make-bytevector length 0)))
      (do ((g 0 (+ g 1))) ((= g groups))
        (let ((triple (+ (* 262144 (vector-ref symbols (* 4 g)))
                         (* 4096 (vector-ref symbols (+ (* 4 g) 1)))
                         (* 64 (vector-ref symbols (+ (* 4 g) 2)))
                         (vector-ref symbols (+ (* 4 g) 3)))))
          (bytevector-u8-set! bytes (* 3 g) (logand (ash triple -16) 255))
          (bytevector-u8-set! bytes (+ (* 3 g) 1) (logand (ash triple -8) 255))
          (bytevector-u8-set! bytes (+ (* 3 g) 2) (logand triple 255))))
      (when (= tail 3)
        (let ((base (* 3 groups))
              (triple (+ (* 262144 (vector-ref symbols (* 4 groups)))
                         (* 4096 (vector-ref symbols (+ (* 4 groups) 1)))
                         (* 64 (vector-ref symbols (+ (* 4 groups) 2))))))
          (bytevector-u8-set! bytes base (logand (ash triple -16) 255))
          (bytevector-u8-set! bytes (+ base 1) (logand (ash triple -8) 255))))
      (when (= tail 2)
        (let ((base (* 3 groups))
              (triple (+ (* 262144 (vector-ref symbols (* 4 groups)))
                         (* 4096 (vector-ref symbols (+ (* 4 groups) 1))))))
          (bytevector-u8-set! bytes base (logand (ash triple -16) 255))))
      bytes)))

(define (base64-encode value)
  "Return the standard, padded, single-line Base64 encoding of the string
   @var{value}."
  (bytes->base64 (string->utf8 value)))

(define (base64-decode value)
  "Decode the Base64 string @var{value} into a string. Whitespace is ignored
   and anything that is not Base64 raises an error."
  (utf8->string (base64->bytes value)))

;; ====== HMAC-SHA256 ======

(define (constant-time-equal? left right)
  "Return #t when the string or bytevector @var{left} holds the same bytes as
   the string or bytevector @var{right}.

   Every byte of the shorter-length comparison is examined, and the differences
   are accumulated before the answer is decided, so the running time depends on
   the length only: an attacker who can time the check learns nothing about how
   many leading bytes were right. Lengths that differ answer #f at once, which
   is the one thing this cannot hide — compare fixed-length material, such as a
   PBKDF2/Argon2 digest, rather than a variable-length password."
  (let ((left-bytes (if (string? left) (string->utf8 left) left))
        (right-bytes (if (string? right) (string->utf8 right) right)))
    (unless (and (bytevector? left-bytes) (bytevector? right-bytes))
      (error
       "bewaking: constant-time-equal? compares two strings or two bytevectors."))
    (let ((length (bytevector-length left-bytes)))
      (if (not (= length (bytevector-length right-bytes)))
          #f
          (let loop ((index 0) (difference 0))
            (if (= index length)
                (zero? difference)
                (loop (+ index 1)
                      (logior difference
                              (logxor (bytevector-u8-ref left-bytes index)
                                      (bytevector-u8-ref right-bytes index))))))))))

(define (hmac-sha256-digest key message)
  "Return the HMAC-SHA256 of the string @var{message} under the string
   @var{key}, as a bytevector. A #f key is treated as the empty key."
  (sign-data (string->utf8 (or key ""))
             (string->utf8 message)
             #:algorithm (mac-algorithm hmac-sha256)))

(define (hmac-sha256-hex key message)
  "Return the HMAC-SHA256 of the string @var{message} under the string
   @var{key}, as a lowercase hexadecimal string."
  (bytes->base16 (hmac-sha256-digest key message)))

;; ====== AES-256-CBC ======

(define (pkcs7-pad bytes)
  "Return @var{bytes} padded to a multiple of the AES block size with PKCS#7
   padding (always at least one byte)."
  (let* ((length (bytevector-length bytes))
         (padding (- block-length (modulo length block-length)))
         (out (make-bytevector (+ length padding) padding)))
    (bytevector-copy! bytes 0 out 0 length)
    out))

(define (pkcs7-unpad bytes)
  "Return @var{bytes} with its PKCS#7 padding removed. Raises an error when the
   length or the padding itself is invalid, which is how a wrong key is
   reported."
  (let* ((length (bytevector-length bytes))
         (padding (if (zero? length) 0 (bytevector-u8-ref bytes (- length 1)))))
    (unless (and (> length 0)
                 (= 0 (modulo length block-length))
                 (> padding 0)
                 (<= padding block-length)
                 (<= padding length))
      (error "bewaking: decryption failed (malformed padding)."))
    (do ((i (- length padding) (+ i 1))) ((= i length))
      (unless (= (bytevector-u8-ref bytes i) padding)
        (error "bewaking: decryption failed (malformed padding).")))
    (bytevector-slice bytes 0 (- length padding))))

(define (call-with-aes-256-cbc key iv proc)
  "Call @var{proc} with an AES-256-CBC cipher handle keyed by @var{key} and
   initialised with @var{iv}, always closing the handle afterwards."
  (let ((key-bytes key)
        (iv-bytes iv))
    (call-with-libgcrypt-handle
     "gcry_cipher_open"
     (lambda (cell)
       (gcry-cipher-open cell gcry-cipher-aes256 gcry-cipher-mode-cbc 0))
     gcry-cipher-close
     (lambda (handle)
       (check-libgcrypt
        (gcry-cipher-setkey handle (bytevector->pointer key-bytes)
                            (bytevector-length key-bytes))
        "gcry_cipher_setkey")
       (check-libgcrypt
        (gcry-cipher-setiv handle (bytevector->pointer iv-bytes)
                           (bytevector-length iv-bytes))
        "gcry_cipher_setiv")
       (proc handle)))))

(define (aes-256-cbc-encrypt key iv plaintext)
  "Encrypt the bytevector @var{plaintext} under @var{key} (32 bytes) and
   @var{iv} (16 bytes), returning a bytevector whose length is a multiple of
   the AES block size. @var{plaintext} must already be padded."
  (let* ((length (bytevector-length plaintext))
         (out (make-bytevector length 0)))
    (unless (= 0 (modulo length block-length))
      (error "bewaking: AES input must be a multiple of the block size."))
    (call-with-aes-256-cbc
     key iv
     (lambda (handle)
       (check-libgcrypt (gcry-cipher-encrypt handle (bytevector->pointer out)
                                             length
                                             (bytevector->pointer plaintext)
                                             length)
                        "gcry_cipher_encrypt")
       out))))

(define (aes-256-cbc-decrypt key iv ciphertext)
  "Decrypt the bytevector @var{ciphertext} under @var{key} (32 bytes) and
   @var{iv} (16 bytes), returning the still-padded plaintext bytevector."
  (let* ((length (bytevector-length ciphertext))
         (out (make-bytevector length 0)))
    (unless (= 0 (modulo length block-length))
      (error "bewaking: AES input must be a multiple of the block size."))
    (call-with-aes-256-cbc
     key iv
     (lambda (handle)
       (check-libgcrypt (gcry-cipher-decrypt handle (bytevector->pointer out)
                                             length
                                             (bytevector->pointer ciphertext)
                                             length)
                        "gcry_cipher_decrypt")
       out))))

;; ====== AES-256-GCM ======
;;
;; GCM is a stream mode with a built-in authentication tag: the ciphertext
;; cannot be altered without the tag failing, and associated data is covered by
;; the tag while travelling in the clear. That makes it a better fit for a
;; sealed envelope than CBC plus a separate HMAC, because there is one key, one
;; operation, and no way to forget the integrity check.

(define gcm-nonce-length
  12)

(define gcm-tag-length
  16)

(define (call-with-aes-256-gcm key nonce proc)
  "Call @var{proc} with an AES-256-GCM cipher handle keyed by @var{key} and
   initialised with the 12-byte @var{nonce}, always closing the handle
   afterwards."
  (let ((key-bytes key)
        (nonce-bytes nonce))
    (call-with-libgcrypt-handle
     "gcry_cipher_open (GCM)"
     (lambda (cell)
       (gcry-cipher-open cell gcry-cipher-aes256 gcry-cipher-mode-gcm 0))
     gcry-cipher-close
     (lambda (handle)
       (check-libgcrypt
        (gcry-cipher-setkey handle (bytevector->pointer key-bytes)
                            (bytevector-length key-bytes))
        "gcry_cipher_setkey (GCM)")
       (check-libgcrypt
        (gcry-cipher-setiv handle (bytevector->pointer nonce-bytes)
                           (bytevector-length nonce-bytes))
        "gcry_cipher_setiv (GCM)")
       (proc handle)))))

(define (gcm-authenticate! handle associated-data)
  "Feed @var{associated-data} to an open GCM @var{handle} as data that is
   authenticated but not encrypted. A #f or empty bytevector authenticates
   nothing."
  (let ((length (if associated-data
                    (bytevector-length associated-data)
                    0)))
    (when (> length 0)
      (check-libgcrypt (gcry-cipher-authenticate
                        handle (bytevector->pointer associated-data) length)
                       "gcry_cipher_authenticate"))))

(define (gcm-finalize! handle)
  "Tell an open GCM @var{handle} that no more data will be supplied, which is
   required before its tag can be read or checked."
  (check-libgcrypt (gcry-cipher-ctl handle gcry-ctl-finalize %null-pointer 0)
                   "gcry_cipher_ctl (GCM finalize)"))

(define (aes-256-gcm-encrypt key nonce plaintext associated-data)
  "Encrypt the bytevector @var{plaintext} under the 32-byte @var{key} and the
   12-byte @var{nonce}, returning @var{plaintext}'s length in ciphertext
   followed by the 16-byte authentication tag. @var{associated-data} is
   authenticated by that tag but not encrypted; it may be #f."
  (let* ((length (bytevector-length plaintext))
         (out (make-bytevector length 0))
         (tag (make-bytevector gcm-tag-length 0)))
    (call-with-aes-256-gcm
     key nonce
     (lambda (handle)
       (gcm-authenticate! handle associated-data)
       (when (> length 0)
         (check-libgcrypt (gcry-cipher-encrypt handle (bytevector->pointer out)
                                               length
                                               (bytevector->pointer plaintext)
                                               length)
                          "gcry_cipher_encrypt (GCM)"))
       (gcm-finalize! handle)
       (check-libgcrypt (gcry-cipher-gettag handle (bytevector->pointer tag)
                                            gcm-tag-length)
                        "gcry_cipher_gettag")))
    (bytes-concatenate out tag)))

(define (aes-256-gcm-decrypt key nonce ciphertext associated-data)
  "Decrypt @var{ciphertext} (ciphertext followed by its 16-byte tag, as
   `aes-256-gcm-encrypt' returns it) under the 32-byte @var{key} and the 12-byte
   @var{nonce}, returning the plaintext bytevector. @var{associated-data} must
   be the same data that was authenticated when encrypting.

   Raises an error when the tag does not match, which is what a wrong key, a
   wrong nonce, altered ciphertext or altered associated data all look like."
  (let* ((length (bytevector-length ciphertext))
         (body-length (- length gcm-tag-length)))
    (unless (>= body-length 0)
      (error
       (format #f
               "bewaking: a GCM ciphertext carries a ~a-byte tag, so it is at least that long."
               gcm-tag-length)))
    (let* ((out (make-bytevector body-length 0))
           (tag (bytevector-slice ciphertext body-length length)))
      (call-with-aes-256-gcm
       key nonce
       (lambda (handle)
         (gcm-authenticate! handle associated-data)
         (when (> body-length 0)
           (check-libgcrypt (gcry-cipher-decrypt
                             handle (bytevector->pointer out) body-length
                             (bytevector->pointer ciphertext) body-length)
                            "gcry_cipher_decrypt (GCM)"))
         (gcm-finalize! handle)
         (unless (= 0 (gcry-cipher-checktag handle (bytevector->pointer tag)
                                            gcm-tag-length))
           (error
            "bewaking: GCM authentication failed. The data was tampered with or the wrong key was used."))))
      out)))

;; ====== Key derivation ======
;;
;; Two key-derivation functions can turn a passphrase into AES key material:
;;
;;   - PBKDF2-HMAC-SHA256 over 10000 iterations, which is exactly what
;;     `openssl enc -aes256 -pbkdf2' uses. It is the default, and the only one
;;     the OpenSSL-compatible format can express, because that format records
;;     no derivation parameters;
;;   - Argon2id, which is memory-hard. libgcrypt 1.11 and newer provide it, and
;;     the parameters used are recorded inside the sealed payload itself.
;;
;; Either way the derivation produces 32 key bytes followed by the 16-byte CBC
;; IV, and the sealed payload is self-describing: `kdf-decrypt' reads the KDF
;; and its parameters back from the bytes it was given, so opening never needs
;; to be told what sealing used, and existing PBKDF2 payloads keep opening.
;;
;; A KDF is described by a symbol or by an alist, so callers can pick parameters
;; without a keyword per parameter:
;;
;;   'pbkdf2                     ; the default
;;   'argon2id                   ; Argon2id with the defaults below
;;   '((kdf . argon2id)
;;     (memory-kib . 262144)     ; 256 MiB
;;     (iterations . 4)          ; passes
;;     (parallelism . 1))        ; lanes

(define default-kdf
  'pbkdf2)

(define default-argon2id-memory-kib
  65536)

(define default-argon2id-iterations
  3)

(define default-argon2id-parallelism
  1)

(define default-argon2id-kdf
  (list (cons 'kdf 'argon2id)
        (cons 'memory-kib default-argon2id-memory-kib)
        (cons 'iterations default-argon2id-iterations)
        (cons 'parallelism default-argon2id-parallelism)))

;; 4 GiB is far past any interactive cost, so this bound only catches a
;; mistyped parameter before it tries to allocate the machine's memory.
(define max-argon2id-memory-kib
  4194304)

;; RFC 9106 caps the lane count at 2^24 - 1, as does libgcrypt.
(define max-argon2id-parallelism
  16777215)

(define max-argon2id-iterations
  4294967295)

(define argon2id-salt-length
  16)

;; libgcrypt's KDF parameter array holds `unsigned long' values. Guile's FFI
;; marshals that type but cannot report its width, so it is taken from the
;; pointer width, which matches `long' on every platform Guile targets (ILP32
;; and LP64); `argon2id-derive' refuses to run where they disagree.
(define unsigned-long-bytes
  (sizeof '*))

(define (unsigned-integer->u32-bytes value)
  "Return the four big-endian bytes of @var{value}, which must fit in 32 bits."
  (let ((bytes (make-bytevector 4 0)))
    (bytevector-uint-set! bytes 0 value (endianness big) 4)
    bytes))

(define (u32-bytes->unsigned-integer bytes offset)
  "Return the 32-bit big-endian integer stored at @var{offset} in @var{bytes}."
  (bytevector-uint-ref bytes offset (endianness big) 4))

(define (argon2id-available?)
  "Return #t when the loaded libgcrypt provides Argon2 (1.11 or newer)."
  (and gcry-kdf-open gcry-kdf-compute gcry-kdf-final #t))

(define (validate-argon2id-parameters memory-kib iterations parallelism)
  "Raise an error unless the Argon2id parameters are usable: a memory cost of
   at least 8 KiB per lane (RFC 9106), at least one pass, at least one lane, and
   values that fit the four bytes each parameter occupies in a sealed payload."
  (unless (and (integer? parallelism)
               (>= parallelism 1)
               (<= parallelism max-argon2id-parallelism))
    (error
     (format #f
             "bewaking: the Argon2id 'parallelism' must be an integer between 1 and ~a."
             max-argon2id-parallelism)))
  (unless (and (integer? memory-kib)
               (>= memory-kib (* 8 parallelism))
               (<= memory-kib max-argon2id-memory-kib))
    (error
     (format #f
             "bewaking: the Argon2id 'memory-kib' must be an integer between ~a (8 KiB per lane) and ~a."
             (* 8 parallelism) max-argon2id-memory-kib)))
  (unless (and (integer? iterations)
               (>= iterations 1)
               (<= iterations max-argon2id-iterations))
    (error
     (format #f
             "bewaking: the Argon2id 'iterations' must be an integer between 1 and ~a."
             max-argon2id-iterations))))

(define* (argon2id-derive password salt length
                          #:key (memory-kib default-argon2id-memory-kib)
                                (iterations default-argon2id-iterations)
                                (parallelism default-argon2id-parallelism)
                                secret associated-data)
  "Derive @var{length} bytes from the string @var{password} and bytevector
   @var{salt} with Argon2id, version 1.3 (19), as specified by RFC 9106.

   #:key memory-kib:  memory cost, in kibibytes (default 65536, i.e. 64 MiB).
   #:key iterations:  time cost, i.e. number of passes (default 3).
   #:key parallelism: number of lanes (default 1).
   #:key secret:      optional bytevector used as Argon2's secret value, called
                      K in RFC 9106. Bewaking's own sealing does not use it, so
                      that the sealed data can be opened with the passphrase
                      alone; it is accepted because a caller with a second key
                      may want it.
   #:key associated-data: optional bytevector used as Argon2's associated data,
                      called X in RFC 9106.

   Raises an error when libgcrypt has no Argon2 support, when the parameters are
   out of range, or when the platform's `unsigned long' does not match the
   pointer width the parameter array is built from.

   #:example
     ;; The Argon2id vector of RFC 9106, Section 5.3.
     (argon2id-derive (make-string 32 (integer->char 1))
                      (make-bytevector 16 2) 32
                      #:memory-kib 32 #:iterations 3 #:parallelism 4
                      #:secret (make-bytevector 8 3)
                      #:associated-data (make-bytevector 12 4))"
  (unless (argon2id-available?)
    (error
     "bewaking: this libgcrypt has no Argon2 support (1.11 or newer is required)."))
  (unless (memv unsigned-long-bytes '(4 8))
    (error
     "bewaking: cannot lay out libgcrypt's Argon2 parameter array on this platform."))
  (for-each (lambda (entry)
              (let ((name (car entry))
                    (value (cdr entry)))
                (unless (or (not value) (bytevector? value))
                  (error
                   (format #f "bewaking: '~a' must be a bytevector." name)))))
            (list (cons 'secret secret)
                  (cons 'associated-data associated-data)))
  (validate-argon2id-parameters memory-kib iterations parallelism)
  (let* ((password-bytes (string->utf8 password))
         (parameters (list length iterations memory-kib parallelism))
         (param-bytes (make-bytevector (* 4 unsigned-long-bytes) 0))
         (out (make-bytevector length 0)))
    (do ((i 0 (+ i 1))) ((= i 4))
      (bytevector-uint-set! param-bytes (* i unsigned-long-bytes)
                            (list-ref parameters i)
                            (native-endianness) unsigned-long-bytes))
    (call-with-libgcrypt-handle
     "gcry_kdf_open (Argon2id)"
     (lambda (cell)
       (gcry-kdf-open cell gcry-kdf-argon2 gcry-kdf-argon2id
                      (bytevector->pointer param-bytes) 4
                      (bytevector->pointer password-bytes)
                      (bytevector-length password-bytes)
                      (bytevector->pointer salt) (bytevector-length salt)
                      (if secret (bytevector->pointer secret) %null-pointer)
                      (if secret (bytevector-length secret) 0)
                      (if associated-data
                          (bytevector->pointer associated-data)
                          %null-pointer)
                      (if associated-data
                          (bytevector-length associated-data)
                          0)))
     gcry-kdf-close
     (lambda (handle)
       (check-libgcrypt (gcry-kdf-compute handle %null-pointer)
                        "gcry_kdf_compute (Argon2id)")
       (check-libgcrypt (gcry-kdf-final handle length
                                        (bytevector->pointer out))
                        "gcry_kdf_final (Argon2id)")))
    out))

(define (kdf-spec kdf)
  "Normalize a key-derivation specification into a complete alist.

   @var{kdf} may be the symbol ~pbkdf2~ (the default), the symbol ~argon2id~,
   or an alist whose ~kdf~ entry names the function and whose remaining entries
   are its parameters, as in ~'((kdf . argon2id) (memory-kib . 262144))~.
   Missing parameters are filled in with the defaults, so the result can be
   handed straight to `kdf-encrypt'. Raises an error for an unknown KDF or an
   out-of-range parameter."
  (let ((alist (cond ((symbol? kdf) (list (cons 'kdf kdf)))
                     ((and (list? kdf) (assoc-ref kdf 'kdf)) kdf)
                     (else (error
                            "bewaking: a KDF must be a symbol or an alist with a 'kdf' entry.")))))
    (let ((name (assoc-ref alist 'kdf)))
      (case name
        ((pbkdf2)
         (let ((iterations (or (assoc-ref alist 'iterations) pbkdf2-iterations)))
           ;; The OpenSSL wire format records no parameters, so an iteration
           ;; count other than the standard one could not be read back.
           (unless (equal? iterations pbkdf2-iterations)
             (error
              (format #f
                      "bewaking: pbkdf2 has a fixed cost of ~a iterations; the OpenSSL format cannot record another."
                      pbkdf2-iterations)))
           (list (cons 'kdf 'pbkdf2) (cons 'iterations pbkdf2-iterations))))
        ((argon2id)
         (let* ((spec (list (cons 'kdf 'argon2id)
                            (cons 'memory-kib
                                  (or (assoc-ref alist 'memory-kib)
                                      default-argon2id-memory-kib))
                            (cons 'iterations
                                  (or (assoc-ref alist 'iterations)
                                      default-argon2id-iterations))
                            (cons 'parallelism
                                  (or (assoc-ref alist 'parallelism)
                                      default-argon2id-parallelism)))))
           (validate-argon2id-parameters (assoc-ref spec 'memory-kib)
                                         (assoc-ref spec 'iterations)
                                         (assoc-ref spec 'parallelism))
           spec))
        (else
         (error
          (format #f
                  "bewaking: unknown key-derivation function '~a' (use pbkdf2 or argon2id)."
                  name)))))))

(define (kdf-name kdf)
  "Return the name of the key-derivation function named by @var{kdf}."
  (assoc-ref (kdf-spec kdf) 'kdf))

(define (kdf-salt-length kdf)
  "Return the salt length, in bytes, that the derivation named by @var{kdf} uses
   inside a sealed payload: 8 for the OpenSSL-compatible PBKDF2 layout, 16 for
   Argon2id. Callers that supply their own salt need this to size it."
  (case (kdf-name kdf)
    ((argon2id) argon2id-salt-length)
    (else salt-length)))

(define* (pbkdf2-sha256 password salt length #:key (iterations pbkdf2-iterations))
  "Derive @var{length} bytes from the string @var{password} and bytevector
   @var{salt} using PBKDF2-HMAC-SHA256 over @var{iterations} iterations."
  (let* ((password-bytes (string->utf8 password))
         (out (make-bytevector length 0)))
    (check-libgcrypt
     (gcry-kdf-derive (bytevector->pointer password-bytes)
                      (bytevector-length password-bytes)
                      gcry-kdf-pbkdf2 gcry-md-sha256
                      (bytevector->pointer salt) (bytevector-length salt)
                      iterations length (bytevector->pointer out))
     "gcry_kdf_derive")
    out))

(define (derive-key-and-iv password salt)
  "Return two values: the 32-byte AES-256 key and the 16-byte CBC IV derived
   from the string @var{password} and bytevector @var{salt}, exactly as OpenSSL
   does for `openssl enc -aes256 -pbkdf2'."
  (let ((material (pbkdf2-sha256 password salt (+ key-length iv-length))))
    (values (bytevector-slice material 0 key-length)
            (bytevector-slice material key-length (+ key-length iv-length)))))

(define (derive-key-material kdf password salt length)
  "Derive @var{length} bytes from the string @var{password} and the bytevector
   @var{salt}, with the key-derivation function described by @var{kdf} (see
   `kdf-spec'). Raises an error for an unknown derivation or for parameters the
   chosen derivation cannot use."
  (let* ((spec (kdf-spec kdf))
         (name (assoc-ref spec 'kdf)))
    (case name
      ((pbkdf2)
       (pbkdf2-sha256 password salt length
                      #:iterations (assoc-ref spec 'iterations)))
      ((argon2id)
       (argon2id-derive password salt length
                        #:memory-kib (assoc-ref spec 'memory-kib)
                        #:iterations (assoc-ref spec 'iterations)
                        #:parallelism (assoc-ref spec 'parallelism)))
      (else
       (error
        (format #f "bewaking: cannot derive key material with the '~a' key derivation."
                name))))))

;; ====== Sealed payloads (salt, key derivation, AES-256-CBC) ======
;;
;; A sealed payload is Base64 over a header, the salt, and the AES-256-CBC
;; ciphertext of the padded plaintext:
;;
;;   PBKDF2   : "Salted__"  salt(8)                     ciphertext
;;   Argon2id : "Argon2id"  salt(16)  m(4)  t(4)  p(4)  ciphertext
;;
;; The PBKDF2 layout is byte-for-byte what
;; `openssl enc -aes256 -pbkdf2 -a -A -k KEY' produces, which is why it cannot
;; carry parameters: there is nowhere in the format to put them. The Argon2id
;; layout adds the memory cost (m, in KiB), the pass count (t) and the lane
;; count (p) as big-endian 32-bit integers, so `kdf-decrypt' can derive the key
;; again from the payload alone, whatever the sealer was configured with.

(define argon2id-header
  "Argon2id")

(define (sealed-argon2id-header-length)
  "The number of bytes a sealed payload spends on the Argon2id header: the
   magic, the salt, and the three 32-bit parameters."
  (+ (string-length argon2id-header) argon2id-salt-length 12))

(define (sealed-payload-header? raw header)
  "Return #t when @var{raw} begins with the eight-byte @var{header}."
  (let ((header-length (string-length header)))
    (and (>= (bytevector-length raw) header-length)
         (string=? (utf8->string (bytevector-slice raw 0 header-length))
                   header))))

(define* (kdf-encrypt plaintext key #:key (kdf default-kdf) salt)
  "Encrypt the string @var{plaintext} under the string @var{key}, deriving the
   AES-256 key and IV with @var{kdf}, and return a Base64 string that records
   which derivation was used.

   #:key kdf:  the key-derivation specification; see `kdf-spec'. Defaults to
               PBKDF2, which produces the OpenSSL-compatible layout.
   #:key salt: the salt bytes to use, 8 for PBKDF2 and 16 for Argon2id;
               defaults to fresh random bytes."
  (let* ((spec (kdf-spec kdf))
         (name (assoc-ref spec 'kdf))
         (plaintext-bytes (string->utf8 plaintext)))
    (case name
      ((pbkdf2)
       (let ((salt (or salt (random-bytes salt-length))))
         (unless (= (bytevector-length salt) salt-length)
           (error "bewaking: a PBKDF2 salt must be 8 bytes long."))
         (let-values (((derived-key derived-iv) (derive-key-and-iv key salt)))
           (bytes->base64
            (bytes-concatenate (string->utf8 openssl-header) salt
                               (aes-256-cbc-encrypt
                                derived-key derived-iv
                                (pkcs7-pad plaintext-bytes)))))))
      ((argon2id)
       (let* ((memory-kib (assoc-ref spec 'memory-kib))
              (iterations (assoc-ref spec 'iterations))
              (parallelism (assoc-ref spec 'parallelism))
              (salt (or salt (random-bytes argon2id-salt-length))))
         (unless (= (bytevector-length salt) argon2id-salt-length)
           (error "bewaking: an Argon2id salt must be 16 bytes long."))
         (let* ((material (argon2id-derive key salt (+ key-length iv-length)
                                           #:memory-kib memory-kib
                                           #:iterations iterations
                                           #:parallelism parallelism))
                (derived-key (bytevector-slice material 0 key-length))
                (derived-iv (bytevector-slice material key-length
                                              (+ key-length iv-length))))
           (bytes->base64
            (bytes-concatenate
             (string->utf8 argon2id-header) salt
             (unsigned-integer->u32-bytes memory-kib)
             (unsigned-integer->u32-bytes iterations)
             (unsigned-integer->u32-bytes parallelism)
             (aes-256-cbc-encrypt derived-key derived-iv
                                  (pkcs7-pad plaintext-bytes)))))))
      (else
       (error
        (format #f "bewaking: cannot seal with the '~a' key derivation."
                name))))))

(define (kdf-decrypt sealed key)
  "Decrypt a Base64 string produced by `kdf-encrypt' (or, for the PBKDF2
   layout, by @code{openssl enc -aes256 -pbkdf2 -a -A}) under the string
   @var{key}, returning the original plaintext string.

   Which key derivation to use, and with which parameters, is read from the
   sealed payload itself, so nothing has to be configured to open old data.
   Raises an error when the payload is not sealed, when its parameters are out
   of range, or when the padding is invalid — as happens with a wrong key."
  (let* ((raw (base64->bytes sealed))
         (length (bytevector-length raw)))
    (cond
     ((sealed-payload-header? raw openssl-header)
      (unless (>= length (+ (string-length openssl-header) salt-length))
        (error "bewaking: truncated OpenSSL-compatible sealed payload."))
      (let* ((salt (bytevector-slice raw (string-length openssl-header)
                                     (+ (string-length openssl-header)
                                        salt-length)))
             (body (bytevector-slice raw (+ (string-length openssl-header)
                                            salt-length)
                                     length)))
        (let-values (((derived-key derived-iv) (derive-key-and-iv key salt)))
          (utf8->string
           (pkcs7-unpad (aes-256-cbc-decrypt derived-key derived-iv body))))))
     ((sealed-payload-header? raw argon2id-header)
      (unless (>= length (sealed-argon2id-header-length))
        (error "bewaking: truncated Argon2id sealed payload."))
      (let* ((m-offset (+ (string-length argon2id-header) argon2id-salt-length))
             (salt (bytevector-slice raw (string-length argon2id-header)
                                     m-offset))
             (memory-kib (u32-bytes->unsigned-integer raw m-offset))
             (iterations (u32-bytes->unsigned-integer raw (+ m-offset 4)))
             (parallelism (u32-bytes->unsigned-integer raw (+ m-offset 8)))
             (body (bytevector-slice raw (+ m-offset 12) length)))
        (validate-argon2id-parameters memory-kib iterations parallelism)
        (let* ((material (argon2id-derive key salt (+ key-length iv-length)
                                          #:memory-kib memory-kib
                                          #:iterations iterations
                                          #:parallelism parallelism))
               (derived-key (bytevector-slice material 0 key-length))
               (derived-iv (bytevector-slice material key-length
                                             (+ key-length iv-length))))
          (utf8->string
           (pkcs7-unpad (aes-256-cbc-decrypt derived-key derived-iv body))))))
     (else
      (error "bewaking: not a sealed payload.")))))

;; ====== Authenticated sealed payloads (AES-256-GCM) ======
;;
;; An authenticated sealed payload is Base16 over a self-describing header and
;; the GCM output:
;;
;;   PBKDF2   : id(1)=1                  salt(16)  nonce(12)  ciphertext tag(16)
;;   Argon2id : id(1)=2  m(4) t(4) p(4)  salt(16)  nonce(12)  ciphertext tag(16)
;;
;; The plaintext needs no padding, because GCM is a stream mode. The tag covers
;; the ciphertext *and* whatever associated data the caller supplies, so a
;; caller can put its own public header under the same seal: alter the header
;; and the tag fails, exactly as altering the ciphertext does.

(define gcm-pbkdf2-id
  1)

(define gcm-argon2id-id
  2)

;; A fresh 16-byte salt per payload, on top of the random nonce: the nonce alone
;; keeps each payload unique, the salt keeps the derived key unique as well.
(define gcm-salt-length
  16)

(define (gcm-kdf-id spec)
  "Return the one-byte identifier recorded for the derivation in @var{spec}."
  (case (assoc-ref spec 'kdf)
    ((pbkdf2) gcm-pbkdf2-id)
    ((argon2id) gcm-argon2id-id)
    (else
     (error
      (format #f "bewaking: cannot seal with the '~a' key derivation."
              (assoc-ref spec 'kdf))))))

(define (gcm-argon2id-parameters spec)
  "Return the three 32-bit big-endian parameter words recorded for the Argon2id
   derivation in @var{spec}, in the order they are read back."
  (bytes-concatenate
   (unsigned-integer->u32-bytes (assoc-ref spec 'memory-kib))
   (unsigned-integer->u32-bytes (assoc-ref spec 'iterations))
   (unsigned-integer->u32-bytes (assoc-ref spec 'parallelism))))

(define* (gcm-encrypt plaintext key #:key (kdf default-kdf) salt nonce
                      associated-data)
  "Seal the bytevector @var{plaintext} under the string @var{key}, deriving the
   32-byte AES-256-GCM key with @var{kdf}, and return a Base16 string that
   records which derivation was used and with which parameters.

   #:key kdf:             the key-derivation specification; see `kdf-spec'.
   #:key salt:            the 16 salt bytes to use; defaults to fresh random bytes.
   #:key nonce:           the 12 nonce bytes to use; defaults to fresh random bytes.
                          It must never repeat under the same key, which is why
                          it defaults to a fresh random value.
   #:key associated-data: optional bytevector that is authenticated together
                          with the ciphertext but stored by the caller. Opening
                          requires the identical bytes."
  (let* ((spec (kdf-spec kdf))
         (name (assoc-ref spec 'kdf))
         (salt (or salt (random-bytes gcm-salt-length)))
         (nonce (or nonce (random-bytes gcm-nonce-length))))
    (unless (= (bytevector-length salt) gcm-salt-length)
      (error
       (format #f "bewaking: a GCM salt must be ~a bytes long."
               gcm-salt-length)))
    (unless (= (bytevector-length nonce) gcm-nonce-length)
      (error
       (format #f "bewaking: a GCM nonce must be ~a bytes long."
               gcm-nonce-length)))
    (let* ((derived-key (derive-key-material spec key salt key-length))
           (header (bytes-concatenate (make-bytevector 1 (gcm-kdf-id spec))
                                      (if (eq? name 'argon2id)
                                          (gcm-argon2id-parameters spec)
                                          (make-bytevector 0 0))
                                      salt
                                      nonce))
           (sealed (aes-256-gcm-encrypt derived-key nonce plaintext
                                        associated-data)))
      (bytes->base16 (bytes-concatenate header sealed)))))

(define (gcm-open-body raw offset spec key associated-data)
  "Read the salt, nonce and ciphertext that start at @var{offset} in @var{raw},
   derive the key with @var{spec} and return the plaintext bytevector."
  (let* ((nonce-offset (+ offset gcm-salt-length))
         (body-offset (+ nonce-offset gcm-nonce-length))
         (salt (bytevector-slice raw offset nonce-offset))
         (nonce (bytevector-slice raw nonce-offset body-offset))
         (sealed (bytevector-slice raw body-offset (bytevector-length raw)))
         (derived-key (derive-key-material spec key salt key-length)))
    (aes-256-gcm-decrypt derived-key nonce sealed associated-data)))

(define* (gcm-decrypt sealed key #:key associated-data)
  "Open a Base16 string produced by `gcm-encrypt' under the string @var{key}, and
   return the plaintext bytevector.

   Which key derivation to use, and with which parameters, is read from the
   sealed payload itself, so nothing has to be configured to open it. The
   recorded parameters are checked before a key is derived from them. Raises an
   error when the payload is malformed or truncated, when its key derivation is
   unknown, or when the authentication tag does not match — as happens with a
   wrong key, altered ciphertext, or associated data that is not the same as
   when the payload was sealed."
  (let* ((raw (base16->bytes sealed))
         (length (bytevector-length raw))
         (minimum (+ 1 gcm-salt-length gcm-nonce-length gcm-tag-length)))
    (unless (>= length minimum)
      (error "bewaking: truncated GCM sealed payload."))
    (case (bytevector-u8-ref raw 0)
      ((1)
       (gcm-open-body raw 1 'pbkdf2 key associated-data))
      ((2)
       (let ((parameter-length 12))
         (unless (>= length (+ minimum parameter-length))
           (error "bewaking: truncated Argon2id sealed payload."))
         (let ((memory-kib (u32-bytes->unsigned-integer raw 1))
               (iterations (u32-bytes->unsigned-integer raw 5))
               (parallelism (u32-bytes->unsigned-integer raw 9)))
           (validate-argon2id-parameters memory-kib iterations parallelism)
           (gcm-open-body raw (+ 1 parameter-length)
                          (list (cons 'kdf 'argon2id)
                                (cons 'memory-kib memory-kib)
                                (cons 'iterations iterations)
                                (cons 'parallelism parallelism))
                          key associated-data))))
      (else
       (error
        (format #f
                "bewaking: unknown key-derivation id ~a in a sealed payload."
                (bytevector-u8-ref raw 0)))))))

;; ====== OpenSSL-compatible sealing ======
;;
;; These two keep the OpenSSL interoperability contract exactly: they always
;; use the PBKDF2 layout, and the reader refuses anything else, so a payload
;; that `openssl-decrypt' accepts is always one the OpenSSL CLI can decrypt too.

(define* (openssl-encrypt plaintext key #:key (salt (random-bytes)))
  "Encrypt the string @var{plaintext} under the string @var{key} and return the
   result as a Base64 string, in the exact format produced by
   @code{openssl enc -aes256 -pbkdf2 -a -A -k KEY}: an 8-byte random salt in a
   @code{Salted__} header followed by the AES-256-CBC ciphertext.

   #:key salt: the 8 salt bytes to use; defaults to fresh random bytes."
  (kdf-encrypt plaintext key #:kdf 'pbkdf2 #:salt salt))

(define (openssl-decrypt ciphertext key)
  "Decrypt a Base64 string produced by `openssl-encrypt' (or by
   @code{openssl enc -aes256 -pbkdf2 -a -A}) under the string @var{key}, and
   return the original plaintext string. Raises an error when the input is not
   in that format or when the padding is invalid, as happens with a wrong key."
  (let ((raw (base64->bytes ciphertext)))
    (unless (sealed-payload-header? raw openssl-header)
      (error "bewaking: not an OpenSSL-compatible sealed payload.")))
  (kdf-decrypt ciphertext key))
