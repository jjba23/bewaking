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
            random-bytes
            openssl-encrypt
            openssl-decrypt))

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
;; The AES and PBKDF2 primitives come from libgcrypt, the library Guile already
;; links against through guile-gcrypt, but which publishes no Scheme bindings
;; for ciphers or key derivation; they are bound here with (system foreign).
;; The encodings are plain Scheme.

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

;; Algorithm and mode identifiers from <gcrypt.h>.
(define gcry-cipher-aes256 9)
(define gcry-cipher-mode-cbc 3)
(define gcry-kdf-pbkdf2 34)
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

(define gcry-strerror
  (libgcrypt-procedure '* "gcry_strerror" (list int)))

(define (check-libgcrypt error-code what)
  "Raise an error unless @var{error-code} reports success, describing @var{what}
   and libgcrypt's own message for the failure."
  (unless (= error-code 0)
    (error (format #f "bewaking: ~a failed: ~a"
                   what
                   (pointer->string (gcry-strerror error-code))))))

;; ====== Randomness ======

(define (bytevector-slice bytes start end)
  "Return a fresh bytevector holding the bytes of @var{bytes} from @var{start}
   up to (but not including) @var{end}."
  (let ((out (make-bytevector (- end start) 0)))
    (bytevector-copy! bytes start out 0 (- end start))
    out))

(define* (random-bytes #:optional (length salt-length))
  "Return a bytevector of @var{length} cryptographically strong random bytes."
  (gen-random-bv length))

;; ====== Base16 (hexadecimal) ======

(define hex-table
  (let ((table (make-vector 256 #f)))
    (do ((i 0 (+ i 1))) ((= i 256) table)
      (vector-set! table i (format #f "~2,'0x" i)))))

(define (bytes->base16 bytes)
  "Return the lowercase hexadecimal encoding of @var{bytes}, one byte per two
   digits."
  (let* ((length (bytevector-length bytes))
         (out (make-string (* 2 length) #\0)))
    (do ((i 0 (+ i 1))) ((= i length) out)
      (let ((digits (vector-ref hex-table (bytevector-u8-ref bytes i))))
        (string-set! out (* 2 i) (string-ref digits 0))
        (string-set! out (+ (* 2 i) 1) (string-ref digits 1))))))

(define (base16-encode value)
  "Return the lowercase hexadecimal encoding of the string @var{value}, one
   byte per two digits."
  (bytes->base16 (string->utf8 value)))

(define (hex-digit-value character)
  "Return the value of the hexadecimal digit @var{character}, accepting both
   cases, or #f when it is not a hexadecimal digit."
  (let ((code (char->integer character)))
    (cond ((and (>= code 48) (<= code 57)) (- code 48))
          ((and (>= code 97) (<= code 102)) (- code 87))
          ((and (>= code 65) (<= code 70)) (- code 55))
          (else #f))))

(define (base16-decode value)
  "Decode the hexadecimal string @var{value} into a string. Upper and lower
   case digits are both accepted. Raises an error when the input has an odd
   number of digits or contains a non-hexadecimal character."
  (unless (string? value)
    (error "bewaking: base16-decode expects a string."))
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
      (utf8->string bytes))))

;; ====== Base64 ======

(define base64-alphabet
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

(define base64-values
  (let ((table (make-vector 256 #f)))
    (do ((i 0 (+ i 1))) ((= i 64) table)
      (vector-set! table (char->integer (string-ref base64-alphabet i)) i))))

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
                       (string-ref base64-alphabet
                                   (logand (ash triple (- (* 6 (- 3 j))))
                                           63))))))
    (unless (zero? rest)
      (let* ((base (* 4 full))
             (a (bytevector-u8-ref bytes (* 3 full)))
             (b (if (= rest 2) (bytevector-u8-ref bytes (+ (* 3 full) 1)) 0))
             (triple (+ (* 65536 a) (* 256 b))))
        (string-set! out base
                     (string-ref base64-alphabet (logand (ash triple -18) 63)))
        (string-set! out (+ base 1)
                     (string-ref base64-alphabet (logand (ash triple -12) 63)))
        (when (= rest 2)
          (string-set! out (+ base 2)
                       (string-ref base64-alphabet
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
  (let* ((key-bytes key)
         (iv-bytes iv)
         (handle-cell (bytevector->pointer (make-bytevector (sizeof '*))))
         (error-code (gcry-cipher-open handle-cell gcry-cipher-aes256
                                       gcry-cipher-mode-cbc 0)))
    (check-libgcrypt error-code "gcry_cipher_open")
    (let ((handle (dereference-pointer handle-cell)))
      (dynamic-wind
        (lambda () #t)
        (lambda ()
          (check-libgcrypt
           (gcry-cipher-setkey handle (bytevector->pointer key-bytes)
                               (bytevector-length key-bytes))
           "gcry_cipher_setkey")
          (check-libgcrypt
           (gcry-cipher-setiv handle (bytevector->pointer iv-bytes)
                              (bytevector-length iv-bytes))
           "gcry_cipher_setiv")
          (proc handle))
        (lambda () (gcry-cipher-close handle))))))

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

;; ====== Key derivation ======

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

;; ====== OpenSSL-compatible sealing ======

(define* (openssl-encrypt plaintext key #:key (salt (random-bytes)))
  "Encrypt the string @var{plaintext} under the string @var{key} and return the
   result as a Base64 string, in the exact format produced by
   @code{openssl enc -aes256 -pbkdf2 -a -A -k KEY}: an 8-byte random salt in a
   @code{Salted__} header followed by the AES-256-CBC ciphertext.

   #:key salt: the 8 salt bytes to use; defaults to fresh random bytes."
  (unless (= (bytevector-length salt) salt-length)
    (error "bewaking: the salt must be 8 bytes long."))
  (let* ((header (string->utf8 openssl-header))
         (header-length (bytevector-length header))
         (body-length (+ header-length salt-length)))
    (let-values (((derived-key derived-iv) (derive-key-and-iv key salt)))
      (let* ((ciphertext (aes-256-cbc-encrypt derived-key derived-iv
                                              (pkcs7-pad (string->utf8 plaintext))))
             (out (make-bytevector (+ body-length (bytevector-length ciphertext)) 0)))
        (bytevector-copy! header 0 out 0 header-length)
        (bytevector-copy! salt 0 out header-length salt-length)
        (bytevector-copy! ciphertext 0 out body-length
                          (bytevector-length ciphertext))
        (bytes->base64 out)))))

(define (openssl-decrypt ciphertext key)
  "Decrypt a Base64 string produced by `openssl-encrypt' (or by
   @code{openssl enc -aes256 -pbkdf2 -a -A}) under the string @var{key}, and
   return the original plaintext string. Raises an error when the input is not
   in that format or when the padding is invalid, as happens with a wrong key."
  (let* ((raw (base64->bytes ciphertext))
         (length (bytevector-length raw))
         (header-length (string-length openssl-header)))
    (unless (and (>= length (+ header-length salt-length))
                 (string=? (utf8->string (bytevector-slice raw 0 header-length))
                           openssl-header))
      (error "bewaking: not an OpenSSL-compatible sealed payload."))
    (let* ((salt (bytevector-slice raw header-length
                                   (+ header-length salt-length)))
           (body (bytevector-slice raw (+ header-length salt-length) length)))
      (let-values (((derived-key derived-iv) (derive-key-and-iv key salt)))
        (utf8->string
         (pkcs7-unpad
          (aes-256-cbc-decrypt derived-key derived-iv body)))))))
