;; bewaking

;; Copyright © Josep Bigorra <jjbigorra@gmail.com>

;; bewaking is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; bewaking is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; Lesser GNU General Public License for more details.

;; You should have received a copy of the GNU Lesser General Public License
;; along with bewaking.  If not, see <https://www.gnu.org/licenses/>.

(define-module (veritas unit crypto-spec)
  #:use-module (veritas veritas)
  #:use-module (rnrs bytevectors)
  #:use-module (bewaking crypto))

;; The cryptographic primitives are checked against published reference values,
;; not against the implementation that produced them:
;;
;;   - HMAC-SHA256 uses the test cases of RFC 4231;
;;   - PBKDF2-HMAC-SHA256 uses the widely published password/salt vectors and
;;     one vector cross-checked with `openssl kdf';
;;   - the AES-256-CBC vectors were produced by OpenSSL 3.5 and are checked in
;;     both directions, so bewaking and `openssl enc' stay interchangeable.
;;
;; None of these tests shells out, so the suite runs with no external tools
;; installed.

(define encryption-key "952e0690-6c3b-4828-b191-961bf98d055c")

;; `openssl enc -aes256 -pbkdf2 -a -A -k <encryption-key>' with the salt
;; 00 01 02 03 04 05 06 07, for the plaintext "bewaking".
(define openssl-fixed-salt
  (let ((salt (make-bytevector 8 0)))
    (do ((i 0 (+ i 1))) ((= i 8) salt)
      (bytevector-u8-set! salt i i))))

(define openssl-fixed-blob
  "U2FsdGVkX18AAQIDBAUGByAGpafcjamTQUX3eOyvQUE=")

;; Produced by `printf %s 'a secret that openssl sealed' |
;;   openssl enc -aes256 -pbkdf2 -a -A -k <encryption-key>'
;; i.e. by OpenSSL itself, with its own random salt.
(define openssl-random-salt-blob
  "U2FsdGVkX19Ul01q1RroU5wq09nZ+ftDyRPwKRg32hSZlll8jqSu+OwtJTiS3T6J")

(define openssl-random-salt-plaintext "a secret that openssl sealed")

(define (raises? thunk)
  "Return #t when calling the zero-argument @var{thunk} raises, else #f."
  (catch #t (lambda () (thunk) #f) (lambda args #t)))

(define base16-suite
  (suite "Base16 encoding"
         (test "known encodings"
               (assert-equal #:expect ""
                             #:got (base16-encode "")
                             #:name "the empty string encodes to nothing")
               (assert-equal #:expect "68656c6c6f"
                             #:got (base16-encode "hello")
                             #:name "lowercase hex digits are produced")
               (assert-equal #:expect "626577616b696e67"
                             #:got (base16-encode "bewaking")
                             #:name "a word encodes byte per byte"))
         (test "decoding accepts both cases"
               (assert-equal #:expect "hello"
                             #:got (base16-decode "68656c6c6f")
                             #:name "lowercase hex decodes")
               (assert-equal #:expect "hello"
                             #:got (base16-decode "68656C6C6F")
                             #:name "uppercase hex decodes too")
               (assert-equal #:expect "hello"
                             #:got (base16-decode (base16-encode "hello"))
                             #:name "encoding then decoding is lossless"))
         (test "malformed input is rejected"
               (assert-error (lambda () (base16-decode "abc"))
                             #:name "an odd number of digits raises")
               (assert-error (lambda () (base16-decode "zz"))
                             #:name "non-hexadecimal characters raise")
               (assert-error (lambda () (base16-decode "68 69"))
                             #:name "embedded whitespace raises"))))

(define base64-suite
  (suite "Base64 encoding"
         (test "RFC 4648 test vectors"
               (assert-equal #:expect "" #:got (base64-encode "")
                             #:name "empty")
               (assert-equal #:expect "Zg==" #:got (base64-encode "f")
                             #:name "one byte of input")
               (assert-equal #:expect "Zm8=" #:got (base64-encode "fo")
                             #:name "two bytes of input")
               (assert-equal #:expect "Zm9v" #:got (base64-encode "foo")
                             #:name "three bytes of input")
               (assert-equal #:expect "Zm9vYg==" #:got (base64-encode "foob")
                             #:name "four bytes of input")
               (assert-equal #:expect "Zm9vYmE=" #:got (base64-encode "fooba")
                             #:name "five bytes of input")
               (assert-equal #:expect "Zm9vYmFy" #:got (base64-encode "foobar")
                             #:name "six bytes of input"))
         (test "decoding is tolerant of line breaks"
               (assert-equal #:expect "hello"
                             #:got (base64-decode "aGVsbG8=\n")
                             #:name "a trailing newline is ignored")
               (assert-equal #:expect "hello world"
                             #:got (base64-decode (base64-encode "hello world"))
                             #:name "encoding then decoding is lossless"))
         (test "malformed input is rejected"
               (assert-error (lambda () (base64-decode "not base64!!"))
                             #:name "non-alphabet characters raise")
               (assert-error (lambda () (base64-decode "Zm9vY"))
                             #:name "a truncated group raises")
               (assert-error (lambda () (base64-decode "Zg==Zg=="))
                             #:name "data after padding raises")
               (assert-error (lambda () (base64-decode "Zg="))
                             #:name "an impossible amount of padding raises"))))

(define hmac-suite
  (suite "HMAC-SHA256 (RFC 4231)"
         (test "RFC 4231 test case 1"
               (assert-equal
                #:expect
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
                #:got (hmac-sha256-hex (make-string 20 (integer->char 11))
                                       "Hi There")
                #:name "a 20-byte key of 0x0b over \"Hi There\""))
         (test "RFC 4231 test case 2"
               (assert-equal
                #:expect
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
                #:got (hmac-sha256-hex "Jefe" "what do ya want for nothing?")
                #:name "the key \"Jefe\" over its test message"))
         (test "the digest is 32 bytes and key-sensitive"
               (assert-equal #:expect 64
                             #:got (string-length (hmac-sha256-hex "key" "msg"))
                             #:name "64 hexadecimal digits, i.e. 32 bytes")
               (assert-false (string=? (hmac-sha256-hex "key" "msg")
                                       (hmac-sha256-hex "other" "msg"))
                             #:name "changing the key changes the MAC"))))

(define pbkdf2-suite
  (suite "PBKDF2-HMAC-SHA256"
         (test "published password/salt vectors"
               (assert-equal
                #:expect
                "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
                #:got (bytes->base16
                       (pbkdf2-sha256 "password" (string->utf8 "salt") 32
                                      #:iterations 1))
                #:name "one iteration")
               (assert-equal
                #:expect
                "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
                #:got (bytes->base16
                       (pbkdf2-sha256 "password" (string->utf8 "salt") 32
                                      #:iterations 2))
                #:name "two iterations")
               (assert-equal
                #:expect
                "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
                #:got (bytes->base16
                       (pbkdf2-sha256 "password" (string->utf8 "salt") 32
                                      #:iterations 4096))
                #:name "4096 iterations"))
         (test "the key and IV material OpenSSL derives"
               (assert-equal
                #:expect
                "cb14e1e1f7ac2fe57f2fcaa462d4ad903867450d9778d2ccf939d8ad3cb99982e0edbd06820c0a636f6fd53d4be339fd"
                #:got (bytes->base16
                       (pbkdf2-sha256 "password" (string->utf8 "salt1234") 48
                                      #:iterations 10000))
                #:name "48 bytes over 10000 iterations, as `openssl kdf' reports"))))

(define openssl-compatibility-suite
  (suite "OpenSSL-compatible sealing"
         (test "a fixed-salt vector matches OpenSSL byte for byte"
               (assert-equal #:expect openssl-fixed-blob
                             #:got (openssl-encrypt "bewaking" encryption-key
                                                    #:salt openssl-fixed-salt)
                             #:name "the ciphertext of a known salt and key")
               (assert-equal #:expect "bewaking"
                             #:got (openssl-decrypt openssl-fixed-blob
                                                    encryption-key)
                             #:name "and it decrypts back"))
         (test "data produced by OpenSSL itself can be opened"
               (assert-equal #:expect openssl-random-salt-plaintext
                             #:got (openssl-decrypt openssl-random-salt-blob
                                                    encryption-key)
                             #:name "an openssl-encrypted string, random salt and all"))
         (test "round-trips"
               (assert-equal #:expect ""
                             #:got (openssl-decrypt
                                    (openssl-encrypt "" encryption-key)
                                    encryption-key)
                             #:name "the empty string round-trips")
               (assert-equal #:expect openssl-random-salt-plaintext
                             #:got (openssl-decrypt
                                    (openssl-encrypt openssl-random-salt-plaintext
                                                     encryption-key)
                                    encryption-key)
                             #:name "a longer payload round-trips")
               (assert-equal #:expect 32
                             #:got (bytevector-length
                                    (base64->bytes (openssl-encrypt ""
                                                                    encryption-key)))
                             #:name "one padded block follows the 16-byte Salted__ header"))
         (test "the salt must be 8 bytes"
               (assert-error (lambda () (openssl-encrypt "x" encryption-key
                                                         #:salt (make-bytevector 4 0)))
                             #:name "a short salt raises"))
         (test "failures are reported rather than ignored"
               (assert-true
                (raises? (lambda ()
                           (openssl-decrypt (openssl-encrypt "secret" encryption-key)
                                            "the-wrong-key")))
                #:name "the wrong key raises")
               (assert-true
                (raises? (lambda ()
                           (openssl-decrypt openssl-fixed-blob "the-wrong-key")))
                #:name "the wrong key raises for OpenSSL-produced data too")
               (assert-true
                (raises? (lambda () (openssl-decrypt "not base64!!" encryption-key)))
                #:name "input that is not Base64 raises")
               (assert-true
                (raises? (lambda ()
                           (openssl-decrypt (base64-encode "twenty three chars...")
                                            encryption-key)))
                #:name "Base64 without a Salted__ header raises")
               (assert-true
                (raises? (lambda ()
                           (openssl-decrypt
                            (string-append "U2FsdGVkX18AAQIDBAUGBy"
                                           (base64-encode "sixteen bytes.."))
                            encryption-key)))
                #:name "a truncated body raises rather than returning garbage"))))

(define (spec)
  (veritas-run base16-suite base64-suite hmac-suite pbkdf2-suite
               openssl-compatibility-suite))
