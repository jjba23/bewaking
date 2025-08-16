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

(define-module (veritas unit bewaking-spec)
  #:use-module (veritas veritas)
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
      (permissions byggsteg:modify-permissions
                   byggsteg:job-create
                   byggsteg:job-delete
                   byggsteg:profile-create
                   byggsteg:profile-delete
                   byggsteg:user-create
                   byggsteg:user-delete))))

(define some-valid-encryption-key
  "952e0690-6c3b-4828-b191-961bf98d055c")

(define some-valid-signing-key
  "503f5869-0a3c-4460-971f-5a88662de3fc")

(define some-valid-token
  "3d4d714938487a384a56717573394169516774775471304b74334e366a665562763051364e733244735461475a6c466d3366384c32666f684e5a79344578494376374a6f7376487169697841677168494e3256414d2b6e7770564359554d36747567633164667250574968714a582f6d544471514a684a346254644f574b32636366795675305a6138503769574d454e395a42524a6342577a56494d6f47445366746548397579444e6e7376615a56784c386f412f326f794d797850627962626667777a39432f344b47384f6f35734c50544470527054665959666562726b78546a654848614d684d6e393462444959593145727156626c67654b47796773525a6e586764466746347845656a667a7869476746712f56587173663063752b677266394f703132695a42734b4c696e7845714a52622f6a6b593636505062316b31644c72714f656474312f4a7a417057704b34566c506361385758517039444471333669307a3035373642794c726c72443875586c6264742f3934654e3361566c56647551586350373371643759414848473830637856644279414f734b39574f79774c417068484a51656a57636935566a794d573975584d385664756133672b395a765864465849713566777636577a596b332f6c495072746770414f415235317579497167486d7470782b533454377054666d5936462f6c42334e4b694163303853357352664f4e7878336a56364d375963676c3464496e634368766774385667586a426f33346745526d56595147796838496470356265586f393063684b705676646a3936385662526245572b6e3458442b436869544774354c506975425432526f75317665493850687234483834304d505a6965334c54345541654c6a54416e492b776f705a716b7342676252443532415a33784e70735278753174344a5642627336666c4c7561505a554c565248664943667a59444656465064544562496e74436a78764452585a6e5555574650484e4551576c77784b3069434c517a6f78345947452b4a7a43775035534c696445352b55436c525136384a6970495279745753643865576b576f734b6431534e7377336d344231506c6a6446374354476b6242617449532f516f535435642b6642493250446232486b6c67446d704630737536716b715033436f63615852504e77356d56565755794576504949782b53386736684b6455304f50454250324865634b2f496e436a4441434f5155356e573352614d694251504a61345a5a2f374a6473796b51747830774d78473267764770766a69384e7652304469703435453848315a6d7251446376704b443230424e6d6844534e6c3377566366366870524d4e714a624d55646a674e4d4a6d6f72525437565355576f39326555554161326c6868783375514b3937697239336a2f376c304e732f5a426a4f78304f372b755177346f7568687071576e4a3676725749744d4c4a4c4e6233554e33536866672f5953454942744f583848675245757a4d56516b565a4e715659343841646c5a44716c7149734a7733527761466f4d7159335456306e6f4751464736366f506370415a74586439757168623237514a7246634d35634c45764e484759325058317551376238687950586f44634d426a3831586b56476473463255")

(define generate-token-suite
  (suite "generate-token"
         (test "works properly with correct details"
               (assert-true (let* ((get-owner-details get-owner-details)
                                   (t (generate-token #:encryption-key
                                       some-valid-encryption-key
                                       #:signing-key some-valid-signing-key
                                       #:get-owner-details get-owner-details)))
                              (display (format #f "\nowner-details: ~s\n"
                                               (get-owner-details)))
                              (display (format #f "\ngenerate-token: ~a\n" t))
                              (and (not (equal? #f t))
                                   (not (equal? "" t))
                                   (not (equal? '() t))))))))

(define decode-token-suite
  (suite "Decryption"
         (test "decrypt-token"
               (assert-false (decrypt-token #:encryption-key
                                            some-valid-encryption-key
                                            #:signing-key "some-signing-key"
                                            #:token some-valid-token)
                             #:name
                             "fails gracefully when signing key is not valid")
               (assert-false (decrypt-token #:encryption-key
                                            some-valid-encryption-key
                                            #:signing-key
                                            some-valid-signing-key
                                            #:token "some-token")
                             #:name "fails gracefully when token is not valid")
               (assert-true (let* ((d (decrypt-token #:encryption-key
                                       some-valid-encryption-key
                                       #:signing-key some-valid-signing-key
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
                                           "someone@jointhefreeworld.org")))
                            #:name "works properly with valid token"))))

(define lossless-token-suite
  (suite "Lossless Token Decryption"
         (test "lossless-token"

               (assert-true (let* ((get-owner-details get-owner-details)
                                   (t (generate-token #:encryption-key
                                       some-valid-encryption-key
                                       #:signing-key some-valid-signing-key
                                       #:get-owner-details get-owner-details))
                                   (d (decrypt-token #:encryption-key
                                       some-valid-encryption-key
                                       #:signing-key some-valid-signing-key
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
                                                      'email))))
                            #:name "works properly with correct details"))))

(define garble-ungarble-string-suite
  (suite "Garbling and Ungarbling"
         (test "garble-ungarble"
               (assert-equal #:expect "dlrow"
                             #:got (string-garble "world"))
               (assert-equal #:expect "lrow"
                             #:got (string-garble "worl"))
               (assert-equal #:expect "row"
                             #:got (string-garble "wor"))
               (assert-equal #:expect "ow"
                             #:got (string-garble "wo"))
               (assert-equal #:expect "w"
                             #:got (string-garble "w"))
               (assert-equal #:expect "dlrow olleh"
                             #:got (string-garble "hello world"))
               (assert-equal #:expect "hello world"
                             #:got (string-ungarble (string-garble
                                                     "hello world")))
               (let ((some-random-string (generate-random-string 128)))
                 (assert-equal #:expect some-random-string
                               #:got (string-ungarble (string-garble
                                                       some-random-string)))))))

(define has-needed-permissions-suite
  (suite "Permissions"
         (test "has-needed-permissions?"
               (assert-false (has-needed-permissions? #:present '()
                                                      #:needed '(admin)))
               (assert-true (has-needed-permissions? #:present '(admin)
                                                     #:needed '(admin)))
               (assert-false (has-needed-permissions? #:present '(reader)
                                                      #:needed '(admin)))
               (assert-true (has-needed-permissions? #:present '(reader admin)
                                                     #:needed '(admin)))
               (assert-true (has-needed-permissions? #:present '(admin reader)
                                                     #:needed '(admin reader)))
               (assert-true (has-needed-permissions? #:present '(reader admin)
                                                     #:needed '(admin reader)))
               (assert-false (has-needed-permissions? #:present '(reader
                                                                  legolas)
                                                      #:needed '(admin reader)))
               (assert-false (has-needed-permissions? #:present '()
                                                      #:needed '(admin reader)))

               )))

(define (spec)
  (veritas-run generate-token-suite decode-token-suite lossless-token-suite
               garble-ungarble-string-suite has-needed-permissions-suite))

