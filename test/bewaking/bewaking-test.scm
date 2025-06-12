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

(define-module (bewaking bewaking-test)
  #:use-module ((srfi srfi-64)
                #:hide (define-test))
  #:use-module (bewaking test-utils)
  #:use-module (bewaking bewaking)
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

(define get-owner-details
  (lambda ()
    `((id . "444959d3-7a8e-455e-b608-31e35145a2fa")
      (email . "someone@jointhefreeworld.org")
      (name . "Legolas son of Thandruil")
      (permissions a
                   b
                   c
                   a:admin
                   b:write
                   c:read))))

(define some-valid-encryption-key
  "952e0690-6c3b-4828-b191-961bf98d055c")

(define some-valid-signing-key
  "503f5869-0a3c-4460-971f-5a88662de3fc")

(define some-valid-token
  "77346f4f51777742626147546634663954344e582f3556336d462b66516533796964306b6d4c373635746f6652754c6e69594d49647a4b444d75456b4f65334c746f622f493031384b79724a65727070766e383365724a7149397132682b304553514a53657747306f782b4474793738534d6e2b41385a5242486d416356594d5a6d7732676e2f4144427069583449734345534c614f2f47456d5472516a7a3843644e3134537539393636384c32554d6b63696a4f66565833786b59734e68596c67326f6f644c7673634e517a4348563268373534317663723853683773516e71544d4554492f4c4d2b457279714271306a47596c72626a5931396d576661317154613766766734637a515a69724e4e6b726675544a3374385746414d48516b79487a4e47397844772f356a323357416f70385a486231626f56646c746e4b7764356f6c705172416d4459556b66414c39594c4d6938357077424837577267596a362f2b722f55742b6f59704b6d474e746e57763676716839496156316330453645386339386564316b4e384d74376e6f552b6d744853714d7778706d7177534445764b613343715957704f4477616e49447345663153714e766931366442342b62526c76323058484948303139766c6765733262445156696435627256594c364a4d796545492b2b494831304554706f667242564e6a4f6e30662f59687848717446655769592b506f4a747663457557626c77633642524c6256512b716c4f777546666e635448727756737969726c676e366a794e4e766d43376b3671784c7242426a452f6c63657059425a3842337261334264716f3161616655344a52325a34323557764857494762776e317175344d464238662b702f41326f4b545371354f37465962434d756a696f61764870727a58465a4c76426a453874574a6c422f59505a6e4358744c5344436f3779587858793546503648774268716d497a3265336e594353424c746b51686a48426d617346346d33376469716c5a625974595a676d5a32572b7537334d6a412f4264763351532b566e4638615243694f4241434b376a4935714a547255616262777a4858564b385a6f6b4364342f435235756c345237347039487339587a555942596c78734e50595a343866555634666f72554530754f523535304f4467337432526463663744566e3443384c676d4b3679383758463737446743436d786979726663416e6e7a3831586b56476473463255")

(define generate-token-test-group
  (test-group "generate-token"
              (test-equal "works properly with correct details" #t
                          (let* ((get-owner-details get-owner-details)
                                 (t (generate-token #:encryption-key
                                                    some-valid-encryption-key
                                                    #:signing-key
                                                    some-valid-signing-key
                                                    #:get-owner-details
                                                    get-owner-details)))
                            (display (format #f "\nowner-details: ~s\n"
                                             (get-owner-details)))
                            (display (format #f "\ngenerate-token: ~a\n" t))
                            (and (not (equal? #f t))
                                 (not (equal? "" t))
                                 (not (equal? '() t)))))))

(define decode-token-test-group
  (test-group "decrypt-token"
              (test-equal
               "fails gracefully when encryption key is not correct" #f
               (decrypt-token #:encryption-key "some-encryption-key"
                              #:signing-key some-valid-signing-key
                              #:token some-valid-token))
              (test-equal "fails gracefully when signing key is not valid" #f
                          (decrypt-token #:encryption-key
                                         some-valid-encryption-key
                                         #:signing-key "some-signing-key"
                                         #:token some-valid-token))
              (test-equal "fails gracefully when token is not valid" #f
                          (decrypt-token #:encryption-key
                                         some-valid-encryption-key
                                         #:signing-key some-valid-signing-key
                                         #:token "some-token"))
              (test-equal "works properly with valid token" #t
                          (let* ((d (decrypt-token #:encryption-key
                                                   some-valid-encryption-key
                                                   #:signing-key
                                                   some-valid-signing-key
                                                   #:token some-valid-token)))
                            (display (format #f "\ndecoded token: ~s\n" d))
                            (and (not (equal? #f d))
                                 (not (equal? "" d))
                                 (not (equal? '() d))
                                 (equal? (assoc-ref d
                                                    'owner-name)
                                         "Legolas son of Thandruil")
                                 (equal? (assoc-ref d
                                                    'owner-email)
                                         "someone@jointhefreeworld.org"))))))

(define lossless-token-test-group
  (test-group "lossless-token"
              (test-equal "works properly with correct details" #t
                          (let* ((get-owner-details get-owner-details)
                                 (t (generate-token #:encryption-key
                                                    some-valid-encryption-key
                                                    #:signing-key
                                                    some-valid-signing-key
                                                    #:get-owner-details
                                                    get-owner-details))
                                 (d (decrypt-token #:encryption-key
                                                   some-valid-encryption-key
                                                   #:signing-key
                                                   some-valid-signing-key
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
                                                    'email)))))))

(define garble-ungarble-string-test-group
  (test-group "garble-ungarble"
              (test-equal "dlrow"
                          (string-garble "world"))
              (test-equal "lrow"
                          (string-garble "worl"))
              (test-equal "row"
                          (string-garble "wor"))
              (test-equal "ow"
                          (string-garble "wo"))
              (test-equal "w"
                          (string-garble "w"))
              (test-equal "dlrow olleh"
                          (string-garble "hello world"))
              (test-equal "hello world"
                          (string-ungarble (string-garble "hello world")))
              (let ((some-random-string (generate-random-string 128)))
                (test-equal some-random-string
                            (string-ungarble (string-garble some-random-string))))))

(define-test test-bewaking generate-token-test-group
             garble-ungarble-string-test-group lossless-token-test-group)
