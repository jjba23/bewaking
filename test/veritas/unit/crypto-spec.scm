;; bewaking
;;
;; SPDX-License-Identifier: MIT
;; Copyright © Josep Bigorra <jjbigorra@gmail.com>

(define-module (veritas unit crypto-spec)
  #:use-module (veritas veritas)
  #:use-module (ice-9 format)
  #:use-module (rnrs bytevectors)
  #:use-module (bewaking crypto))

;; The cryptographic primitives are checked against published reference values,
;; not against the implementation that produced them:
;;
;;   - HMAC-SHA256 uses the test cases of RFC 4231;
;;   - PBKDF2-HMAC-SHA256 uses the widely published password/salt vectors and
;;     one vector cross-checked with `openssl kdf';
;;   - the AES-256-CBC vectors were produced by OpenSSL 3.5 and are checked in
;;     both directions, so bewaking and `openssl enc' stay interchangeable;
;;   - the AES-256-GCM payloads were produced by Python's `cryptography' and are
;;     matched byte for byte, under both key derivations;
;;   - Argon2id uses the test vector of RFC 9106, Section 5.3, which pins the
;;     parameter order, the lane count and the variant, none of which the
;;     implementation could tell us about itself.
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

;; A cheap Argon2id specification, so the suite stays fast: the cost of a
;; derivation is a property of the parameters, not of the code path.
(define cheap-argon2id
  '((kdf . argon2id) (memory-kib . 8192) (iterations . 1) (parallelism . 1)))

(define argon2id-suite
  (suite "Argon2id key derivation (RFC 9106)"
         (test "the RFC 9106 Argon2id vector is reproduced"
               ;; P = 32 x 01, S = 16 x 02, K = 8 x 03, X = 12 x 04,
               ;; p = 4, T = 32, m = 32 KiB, t = 3.
               (assert-equal #:expect
                             "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
                             #:got
                             (bytes->base16
                              (argon2id-derive (make-string 32 (integer->char 1))
                                               (make-bytevector 16 2) 32
                                               #:memory-kib 32 #:iterations 3
                                               #:parallelism 4
                                               #:secret (make-bytevector 8 3)
                                               #:associated-data
                                               (make-bytevector 12 4)))
                             #:name "password 32x01, salt 16x02, secret 8x03, data 12x04, m=32, t=3, p=4"))
         (test "every parameter changes the derived bytes"
               (assert-false (equal? (argon2id-derive "key" (make-bytevector 16 1) 32
                                                       #:memory-kib 8192 #:iterations 1)
                                     (argon2id-derive "key" (make-bytevector 16 1) 32
                                                       #:memory-kib 8192 #:iterations 2))
                             #:name "a different pass count gives a different tag")
               (assert-false (equal? (argon2id-derive "key" (make-bytevector 16 1) 32
                                                       #:memory-kib 8192)
                                     (argon2id-derive "key" (make-bytevector 16 2) 32
                                                       #:memory-kib 8192))
                             #:name "a different salt gives a different tag")
               (assert-false (equal? (argon2id-derive "key" (make-bytevector 16 1) 32
                                                       #:memory-kib 8192)
                                     (argon2id-derive "other" (make-bytevector 16 1) 32
                                                       #:memory-kib 8192))
                             #:name "a different passphrase gives a different tag"))
         (test "invalid parameters are rejected"
               (assert-true (raises? (lambda ()
                                       (argon2id-derive "key" (make-bytevector 16 1)
                                                        32 #:memory-kib 4)))
                            #:name "less than 8 KiB per lane is refused")
               (assert-true (raises? (lambda ()
                                       (argon2id-derive "key" (make-bytevector 16 1)
                                                        32 #:iterations 0)))
                            #:name "zero passes is refused")
               (assert-true (raises? (lambda ()
                                       (argon2id-derive "key" (make-bytevector 16 1)
                                                        32 #:parallelism 0)))
                            #:name "zero lanes is refused")
               (assert-true (raises? (lambda ()
                                       (argon2id-derive "key" (make-bytevector 16 1)
                                                        32 #:memory-kib "lots")))
                            #:name "a non-integer memory cost is refused")
               (assert-true (raises? (lambda ()
                                       (argon2id-derive "key" (make-bytevector 16 1)
                                                        32 #:secret "not-bytes")))
                            #:name "a non-bytevector secret is refused")
               (assert-true (argon2id-available?)
                            #:name "this libgcrypt provides Argon2"))))

(define kdf-spec-suite
  (suite "Key-derivation specifications"
         (test "the default is PBKDF2 with its fixed cost"
               (assert-equal #:expect 'pbkdf2 #:got (kdf-name default-kdf)
                             #:name "the module default names PBKDF2")
               (assert-equal #:expect 10000
                             #:got (assoc-ref (kdf-spec 'pbkdf2) 'iterations)
                             #:name "its iteration count is the OpenSSL one"))
         (test "Argon2id defaults are filled in and reported"
               (assert-equal #:expect
                             '((kdf . argon2id) (memory-kib . 65536)
                               (iterations . 3) (parallelism . 1))
                             #:got (kdf-spec 'argon2id)
                             #:name "the defaults are 64 MiB, 3 passes, 1 lane")
               (assert-equal #:expect
                             '((kdf . argon2id) (memory-kib . 262144)
                               (iterations . 4) (parallelism . 1))
                             #:got (kdf-spec '((kdf . argon2id)
                                               (memory-kib . 262144)
                                               (iterations . 4)))
                             #:name "given parameters are kept and the rest defaulted"))
         (test "unsupported specifications are refused"
               (assert-true (raises? (lambda () (kdf-spec 'scrypt)))
                            #:name "an unknown KDF name is refused")
               (assert-true (raises? (lambda () (kdf-spec "pbkdf2")))
                            #:name "a string is not a KDF specification")
               (assert-true (raises? (lambda ()
                                       (kdf-spec '((kdf . pbkdf2)
                                                   (iterations . 5000)))))
                            #:name "a PBKDF2 cost the OpenSSL format cannot record is refused")
               (assert-true (raises? (lambda ()
                                       (kdf-spec '((kdf . argon2id)
                                                   (memory-kib . 4)))))
                            #:name "an out-of-range Argon2id memory cost is refused"))))

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

(define (sealed-with-argon2id)
  "An Argon2id sealed payload with a fixed salt, for inspecting its layout."
  (kdf-encrypt "a payload" encryption-key #:kdf cheap-argon2id
               #:salt (make-bytevector 16 9)))

(define (sealed-with-default-kdf)
  (kdf-encrypt "bewaking" encryption-key #:kdf 'pbkdf2
               #:salt openssl-fixed-salt))

(define (recorded-header blob)
  ;; R6RS bytevector-copy takes no range, so copy the header out by hand.
  (let ((header (make-bytevector 8 0)))
    (bytevector-copy! (base64->bytes blob) 0 header 0 8)
    (utf8->string header)))

(define (recorded-u32 blob offset)
  (bytevector-uint-ref (base64->bytes blob) offset (endianness big) 4))

(define (tampered-argon2id-blob)
  "The sealed payload with its recorded pass count changed, which must not be
   silently accepted as another valid derivation."
  (let ((raw (base64->bytes (sealed-with-argon2id))))
    (bytevector-u8-set! raw 31 (logxor 1 (bytevector-u8-ref raw 31)))
    (bytes->base64 raw)))

(define (argon2id-blob-opens?)
  (string=? "a payload" (kdf-decrypt (sealed-with-argon2id) encryption-key)))

(define (argon2id-blob-rejects-wrong-key?)
  (raises? (lambda () (kdf-decrypt (sealed-with-argon2id) "another-key"))))

(define (openssl-reader-refuses-argon2id?)
  (raises? (lambda () (openssl-decrypt (sealed-with-argon2id) encryption-key))))

(define (kdf-reader-opens-openssl-blobs?)
  (string=? openssl-random-salt-plaintext
            (kdf-decrypt openssl-random-salt-blob encryption-key)))

(define sealed-payload-suite
  (suite "Sealed payloads (key derivation is recorded)"
         (test "the default KDF keeps the OpenSSL layout byte for byte"
               (assert-true (string=? openssl-fixed-blob (sealed-with-default-kdf))
                            #:name "a fixed-salt PBKDF2 payload equals OpenSSL's own output"))
         (test "an Argon2id payload records its derivation and parameters"
               (assert-equal #:expect "Argon2id"
                             #:got (recorded-header (sealed-with-argon2id))
                             #:name "the header names the derivation")
               (assert-equal #:expect 8192
                             #:got (recorded-u32 (sealed-with-argon2id) 24)
                             #:name "the memory cost is recorded, in KiB")
               (assert-equal #:expect 1
                             #:got (recorded-u32 (sealed-with-argon2id) 28)
                             #:name "the pass count is recorded")
               (assert-equal #:expect 1
                             #:got (recorded-u32 (sealed-with-argon2id) 32)
                             #:name "the lane count is recorded"))
         (test "an Argon2id payload round-trips and resists the wrong key"
               (assert-true (argon2id-blob-opens?)
                            #:name "the same key opens it")
               (assert-true (argon2id-blob-rejects-wrong-key?)
                            #:name "another key does not"))
         (test "tampering with the recorded parameters is not honoured"
               (assert-true (raises? (lambda ()
                                       (kdf-decrypt (tampered-argon2id-blob)
                                                    encryption-key)))
                            #:name "a changed pass count no longer decrypts"))
         (test "both readers keep their contracts"
               (assert-true (openssl-reader-refuses-argon2id?)
                            #:name "openssl-decrypt refuses what the OpenSSL CLI could not read")
               (assert-true (kdf-reader-opens-openssl-blobs?)
                            #:name "kdf-decrypt opens payloads produced by OpenSSL"))
         (test "sizes and headers are validated"
               (assert-true (raises? (lambda ()
                                       (kdf-encrypt "x" encryption-key
                                                    #:kdf 'argon2id
                                                    #:salt (make-bytevector 8 1))))
                            #:name "an 8-byte Argon2id salt is refused")
               (assert-true (raises? (lambda ()
                                       (kdf-encrypt "x" encryption-key
                                                    #:kdf 'pbkdf2
                                                    #:salt (make-bytevector 16 1))))
                            #:name "a 16-byte PBKDF2 salt is refused")
               (assert-true (raises? (lambda ()
                                       (kdf-decrypt
                                        (bytes->base64 (string->utf8 "NoSuch__header"))
                                        encryption-key)))
                            #:name "a payload with no known header is refused"))))

;; ====== Authenticated payloads (AES-256-GCM) ======
;;
;; The two reference payloads below were produced by an independent
;; implementation: Python's `cryptography', AESGCM over PBKDF2-HMAC-SHA256 and
;; over Argon2id, with the same salt, nonce and associated data. Matching them
;; byte for byte pins the container layout, the order of the derivation and the
;; tag, none of which a check against bewaking itself could pin.

(define gcm-salt
  (make-bytevector 16 7))

(define gcm-nonce
  (make-bytevector 12 9))

(define gcm-associated-data
  "BWK3.default.1791715315.-")

(define gcm-plaintext
  "the plaintext of an authenticated payload")

(define gcm-pbkdf2-payload
  (string-append
   "010707070707070707070707070707070709090909090909090909090915"
   "d0ed647041883a00a39c1a98153992e43396ca2ef78f30cf603552820a8e"
   "d81e320d38a87aee14ad4a7f41b2df7b369d6614500294e59e58"
   ""))

(define gcm-argon2id-payload
  (string-append
   "020000200000000001000000010707070707070707070707070707070709"
   "090909090909090909090996b424d50c29974261cc56650752a5237f7528"
   "271202d70046f0bc49c8c0bfefb86150c0b946a554a1590bec6d5f03409b"
   "bff197af7d782651"))

(define (sealed-authenticated-payload kdf)
  (gcm-encrypt (string->utf8 gcm-plaintext) encryption-key
               #:kdf kdf #:salt gcm-salt #:nonce gcm-nonce
               #:associated-data (string->utf8 gcm-associated-data)))

(define* (authenticated-payload-open? sealed
                                     #:optional (associated-data gcm-associated-data))
  (string=? gcm-plaintext
            (utf8->string (gcm-decrypt sealed encryption-key
                                       #:associated-data
                                       (string->utf8 associated-data)))))

(define* (authenticated-payload-refused? sealed
                                         #:key (associated-data gcm-associated-data)
                                               (key encryption-key))
  (raises? (lambda ()
             (gcm-decrypt sealed key
                          #:associated-data (string->utf8 associated-data)))))

(define (authenticated-payload-byte sealed offset)
  (bytevector-u8-ref (base16->bytes sealed) offset))

(define (authenticated-payload-u32 sealed offset)
  (bytevector-uint-ref (base16->bytes sealed) offset (endianness big) 4))

(define (flipped-hex-digit sealed index)
  "Return @var{sealed} with the hexadecimal digit at @var{index} replaced by a
   different one, to simulate tampering."
  (let* ((character (string-ref sealed index))
         (replacement (if (char=? character #\0) #\1 #\0)))
    (string-append (substring sealed 0 index)
                   (string replacement)
                   (substring sealed (+ index 1) (string-length sealed)))))

(define authenticated-payload-suite
  (suite "Authenticated payloads (AES-256-GCM)"
         (test "the payload is byte for byte the reference implementation's"
               (assert-equal
                #:expect gcm-pbkdf2-payload
                #:got (sealed-authenticated-payload 'pbkdf2)
                #:name "PBKDF2-HMAC-SHA256, as Python's cryptography seals it")
               (assert-equal
                #:expect gcm-argon2id-payload
                #:got (sealed-authenticated-payload cheap-argon2id)
                #:name "Argon2id with its parameters recorded, likewise"))
         (test "the payload records which derivation to use"
               (assert-equal #:expect 1
                             #:got (authenticated-payload-byte
                                    (sealed-authenticated-payload 'pbkdf2) 0)
                             #:name "PBKDF2 is identified by its own id")
               (assert-equal #:expect 2
                             #:got (authenticated-payload-byte
                                    (sealed-authenticated-payload cheap-argon2id) 0)
                             #:name "Argon2id is identified by a different id")
               (assert-equal #:expect 8192
                             #:got (authenticated-payload-u32
                                    (sealed-authenticated-payload cheap-argon2id) 1)
                             #:name "the memory cost is recorded, in KiB")
               (assert-equal #:expect 1
                             #:got (authenticated-payload-u32
                                    (sealed-authenticated-payload cheap-argon2id) 5)
                             #:name "the pass count is recorded")
               (assert-equal #:expect 1
                             #:got (authenticated-payload-u32
                                    (sealed-authenticated-payload cheap-argon2id) 9)
                             #:name "the lane count is recorded"))
         (test "fresh salt and nonce still round-trip"
               (assert-true (authenticated-payload-open?
                             (sealed-authenticated-payload 'pbkdf2))
                            #:name "a payload sealed with random salt and nonce opens")
               (assert-true (authenticated-payload-open?
                             (sealed-authenticated-payload cheap-argon2id))
                            #:name "and so does an Argon2id one")
               (assert-true (authenticated-payload-open?
                             (gcm-encrypt (string->utf8 gcm-plaintext) encryption-key)
                             "")
                            #:name "associated data is optional: empty means none")
               (assert-true (authenticated-payload-refused?
                             (gcm-encrypt (string->utf8 gcm-plaintext) encryption-key))
                            #:name "a payload sealed without it does not open with it"))
         (test "the tag refuses every alteration"
               ;; Digits: 0-1 are the derivation id, 2-33 the salt, 34-57 the
               ;; nonce, then the ciphertext, then the 32 digits of the tag.
               (assert-true (authenticated-payload-refused?
                             (flipped-hex-digit gcm-pbkdf2-payload 60))
                            #:name "a flipped ciphertext digit is refused")
               (assert-true (authenticated-payload-refused?
                             (flipped-hex-digit gcm-pbkdf2-payload
                                               (- (string-length gcm-pbkdf2-payload) 1)))
                            #:name "a flipped tag digit is refused")
               (assert-true (authenticated-payload-refused?
                             (flipped-hex-digit gcm-pbkdf2-payload 0))
                            #:name "an unknown key-derivation id is refused, not guessed at")
               (assert-true (authenticated-payload-refused?
                             gcm-pbkdf2-payload
                             #:associated-data "BWK3.default.1791715316.-")
                            #:name "different associated data is refused")
               (assert-true (authenticated-payload-refused?
                             gcm-pbkdf2-payload #:key "another-key")
                            #:name "the wrong key is refused")
               (assert-true (authenticated-payload-refused?
                             (substring gcm-pbkdf2-payload 0 40))
                            #:name "a truncated payload is refused"))
         (test "hexadecimal that stands for bytes decodes to bytes"
               (assert-true (bytevector? (base16->bytes "00ff"))
                            #:name "base16->bytes returns a bytevector")
               (assert-equal #:expect 255
                             #:got (bytevector-u8-ref (base16->bytes "00ff") 1)
                             #:name "and keeps the raw octets, which base16-decode cannot"))))

;; ====== The building blocks the payload format is assembled from ======
;;
;; The reference vectors above pin *what* the primitives compute. These check
;; the properties the payload format depends on: that the key material comes
;; from the named derivation, that every recorded parameter is actually used,
;; that fresh randomness is fresh, and that bytes survive the encodings.

(define (all-same-byte? bytes)
  (let ((first (bytevector-u8-ref bytes 0)))
    (let loop ((i 1))
      (cond ((= i (bytevector-length bytes)) #t)
            ((= first (bytevector-u8-ref bytes i)) (loop (+ i 1)))
            (else #f)))))

(define (bytes-distinct? a b)
  (not (equal? a b)))

(define kdf-material-suite
  (suite "Derived key material"
         (test "PBKDF2 key material is the PBKDF2 derivation's"
               (assert-equal
                #:expect
                (bytes->base16
                 (pbkdf2-sha256 "key" (make-bytevector 8 3) 32
                                #:iterations 10000))
                #:got
                (bytes->base16
                 (derive-key-material 'pbkdf2 "key" (make-bytevector 8 3) 32))
                #:name "derive-key-material agrees with the primitive it names")
               (assert-equal #:expect 32
                             #:got (bytevector-length
                                    (derive-key-material 'pbkdf2 "key"
                                                         (make-bytevector 8 3)
                                                         32))
                             #:name "the requested length is produced"))
         (test "Argon2id key material honours its parameters"
               (assert-equal #:expect 48
                             #:got (bytevector-length
                                    (derive-key-material cheap-argon2id "key"
                                                         (make-bytevector 16 3)
                                                         48))
                             #:name "the full key-and-IV length can be derived")
               (assert-true
                (bytes-distinct?
                 (derive-key-material cheap-argon2id "key" (make-bytevector 16 3)
                                      32)
                 (derive-key-material '((kdf . argon2id) (memory-kib . 8192)
                                        (iterations . 2) (parallelism . 1))
                                      "key" (make-bytevector 16 3) 32))
                #:name "changing the pass count changes the material")
               (assert-true
                (bytes-distinct?
                 (derive-key-material cheap-argon2id "key" (make-bytevector 16 3)
                                      32)
                 (derive-key-material cheap-argon2id "another-key"
                                      (make-bytevector 16 3) 32))
                #:name "changing the passphrase changes the material"))
         (test "an unknown derivation is refused"
               (assert-true (raises? (lambda ()
                                       (derive-key-material 'scrypt "key"
                                                            (make-bytevector 8 3)
                                                            32)))
                            #:name "no other function can be named"))))

(define randomness-suite
  (suite "Randomness"
         (test "random-bytes returns genuinely fresh bytes"
               (assert-equal #:expect 8 #:got (bytevector-length (random-bytes))
                             #:name "the default length is the OpenSSL salt length")
               (assert-equal #:expect 32
                             #:got (bytevector-length (random-bytes 32))
                             #:name "the requested length is honoured")
               (assert-true (bytes-distinct? (random-bytes 32) (random-bytes 32))
                            #:name "two calls do not return the same bytes")
               (assert-false (all-same-byte? (random-bytes 32))
                             #:name "a draw is not a constant")
               (assert-true (bytes-distinct? (random-bytes 16) (make-bytevector 16 0))
                            #:name "a draw is not all zeroes"))))

(define byte-encoding-suite
  (suite "Encodings of raw bytes"
         (test "Base16 round-trips arbitrary bytevectors"
               (assert-true (equal? (make-bytevector 0 0)
                                    (base16->bytes (bytes->base16
                                                    (make-bytevector 0 0))))
                            #:name "the empty bytevector round-trips")
               (assert-true (equal? (make-bytevector 16 255)
                                    (base16->bytes (bytes->base16
                                                    (make-bytevector 16 255))))
                            #:name "bytes that are not valid UTF-8 survive the round trip"))
         (test "Base64 round-trips arbitrary bytevectors"
               (assert-equal #:expect 3
                             #:got (bytevector-length
                                    (base64->bytes (bytes->base64
                                                    (make-bytevector 3 7))))
                             #:name "bytes that are not valid UTF-8 survive the round trip"))))

(define (refused-with-message? thunk needle)
  "Return #t when calling @var{thunk} raises an error whose text mentions
   @var{needle}, so a test can tell *which* refusal happened rather than only
   that something was refused."
  (catch #t (lambda () (thunk) #f)
         (lambda args
           (let ((text (format #f "~a" args)))
             (and (string-contains text needle) #t)))))

(define (crafted-argon2id-payload memory-kib iterations parallelism)
  "A GCM payload an untrusted client could send: the Argon2id id, the client's
   own cost parameters, a salt, a nonce and a junk tag. Nothing about it is
   authentic; the point is what a receiver is asked to *spend* before it can
   tell, which is why the recorded parameters must be bounded on arrival."
  (let ((raw (make-bytevector (+ 1 12 16 12 16) 0)))
    (bytevector-u8-set! raw 0 2)
    (bytevector-uint-set! raw 1 memory-kib (endianness big) 4)
    (bytevector-uint-set! raw 5 iterations (endianness big) 4)
    (bytevector-uint-set! raw 9 parallelism (endianness big) 4)
    (bytes->base16 raw)))

(define gcm-hygiene-suite
  (suite "Authenticated payload hygiene"
         (test "every payload uses a fresh salt and nonce"
               ;; `sealed-authenticated-payload' above pins the format with a
               ;; fixed salt and nonce; here the defaults must draw their own.
               (let ((a (gcm-encrypt (string->utf8 gcm-plaintext) encryption-key))
                     (b (gcm-encrypt (string->utf8 gcm-plaintext) encryption-key)))
                 (assert-false (string=? a b)
                               #:name "sealing the same plaintext twice does not repeat the payload")
                 (assert-false (string=? (substring a 2 34) (substring b 2 34))
                               #:name "the recorded salts differ, so the derived keys do too")
                 (assert-false (string=? (substring a 34 58) (substring b 34 58))
                               #:name "the recorded nonces differ as well")))
         (test "the salt and the nonce are used, not decorative"
               (assert-true (authenticated-payload-refused?
                             (flipped-hex-digit gcm-pbkdf2-payload 26))
                            #:name "editing a salt digit breaks the tag")
               (assert-true (authenticated-payload-refused?
                             (flipped-hex-digit gcm-pbkdf2-payload 58))
                            #:name "editing a nonce digit breaks the tag")
               (assert-true (authenticated-payload-refused?
                             (flipped-hex-digit gcm-argon2id-payload 2))
                            #:name "editing an Argon2id parameter digit is refused"))
         (test "the associated data is authenticated but not stored"
               (assert-false (string-contains (sealed-authenticated-payload 'pbkdf2)
                                              (base16-encode gcm-associated-data))
                             #:name "the associated data does not appear in the payload")
               (assert-true (authenticated-payload-refused?
                             (sealed-authenticated-payload 'pbkdf2)
                             #:associated-data (string-append gcm-associated-data
                                                             "!"))
                            #:name "one extra associated-data byte breaks the tag"))
         (test "an empty plaintext is still authenticated"
               (assert-true
                (string=? ""
                          (utf8->string
                           (gcm-decrypt (gcm-encrypt (make-bytevector 0 0)
                                                     encryption-key)
                                        encryption-key)))
                #:name "the empty plaintext round-trips")
               (assert-true (>= (string-length
                                 (gcm-encrypt (make-bytevector 0 0) encryption-key))
                                (* 2 (+ 1 16 12 16)))
                            #:name "even an empty payload carries a salt, a nonce and a tag"))
         (test "the recorded derivation cost is bounded before it is spent"
               ;; The Argon2id parameters travel *inside* the payload, so an
               ;; attacker chooses them. They are validated before any memory is
               ;; allocated or any pass is run, so a crafted body is refused
               ;; rather than obeyed; the messages name Argon2id, which is how
               ;; these tests know the refusal is the bound and not a failed tag.
               (assert-true (refused-with-message?
                             (lambda ()
                               (gcm-decrypt
                                (crafted-argon2id-payload 4194305 1 1)
                                encryption-key))
                             "Argon2id")
                            #:name "a memory cost above the cap is refused, not allocated")
               (assert-true (refused-with-message?
                             (lambda ()
                               (gcm-decrypt
                                (crafted-argon2id-payload 8 1 16777216)
                                encryption-key))
                             "Argon2id")
                            #:name "a lane count above the cap is refused")
               (assert-true (refused-with-message?
                             (lambda ()
                               (gcm-decrypt
                                (crafted-argon2id-payload 8 0 1)
                                encryption-key))
                             "Argon2id")
                            #:name "a zero pass count is refused")
               (assert-true (refused-with-message?
                             (lambda ()
                               (gcm-decrypt
                                (crafted-argon2id-payload 8 1 2)
                                encryption-key))
                             "Argon2id")
                            #:name "less than 8 KiB per lane is refused")
               (assert-true (refused-with-message?
                             (lambda ()
                               (gcm-decrypt
                                (crafted-argon2id-payload 8192 1 1)
                                encryption-key))
                             "GCM authentication failed")
                            #:name "a cost inside the bounds is derived, then fails the tag: the bound is not a blanket refusal"))))

(define (spec)
  (veritas-run base16-suite base64-suite hmac-suite pbkdf2-suite
               argon2id-suite kdf-spec-suite sealed-payload-suite
               authenticated-payload-suite
               openssl-compatibility-suite
               kdf-material-suite randomness-suite byte-encoding-suite
               gcm-hygiene-suite))
