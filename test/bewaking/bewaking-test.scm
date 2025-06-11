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
    `((id unquote
          (generate-string-uuid))
      (email unquote
             (generate-random-string 36))
      (name unquote
            (generate-random-string 12))
      (permissions unquote
                   (list (string->symbol (generate-random-string 16))
                         (string->symbol (generate-random-string 16))
                         (string->symbol (generate-random-string 16)))))))

(define some-valid-uuid
  "952e0690-6c3b-4828-b191-961bf98d055c")

;; decoded token: ((token-type . bewaking-token) (token-id . "2dfba783-ebe4-4ef0-acee-429d28b89ca8")
;; (token-created-at . 1749673042) (token-expires-at . 1749932242) (owner-id . "640d5fce-fea7-482f-88ec-d48b23ae86ed")
;; (owner-email . "hus1ktghpbqm3m7ll9w9aywhek7c96178nmr") (owner-name . "vyg333wzj203")
;; (owner-permissions 1h7kveftmcp6zqun db1o1f4qglyihwhp e5ezkef6vu1ua0aq))
(define some-valid-token
  "=AKpfyazV6CAuMKjbD/onNSv9zBlr+3AD2bDyVlTvlTMCfq06U43xAJUfspf/AJDlvPkYDtq0KQchXrvI773dWh9SguSFZ7u+KNy1KCC/AF8k3MUEM5E4n38eAU2fxuVC9YkPUR30u4uVk0CxGlJcIJBvB33XRFh8PtRthJHW/W+8vxJ64TaUtX7J+r9QGDADEW8bPzwM+WKOoxL+uD5vi5MMXS+C1Edwi04yM0X5jQUOD+gLYWliVL1hVeTcg7jz3a0dIeAmzGF4M9urvZxeTWiAzCDC+Lhl/Q0dK86c+9BqBbDuIvipnw77MfgUp48nFVlYGkt9ha1UdzyfFuuXEF69JNm5F9cFN1q1ToFr2uG7sMOI7S8j96gKGQCPZMyz3mPSeFVaMQlyoKxoXSArfbonKztXlxlUsKtlWvD42KmJiuZ83B+Rj9wnlFkWeaOcFJxcptHQhwL5YLJwbrdrHa6fixcoqbzMWbv5pZXbpBJn37XaOVYcuz8VY74qTCDFIK7VK+olIGUCPpXSbVkuzUrChMarwp6Vx+BLU58DCPmbhVH3K+jTbs/Mb4LTQ7zWdQH2R5tIx6cif3Uf3Q3FHQUoQEsZOt+87ElD73YkDpUoVDtLI7ZwiJz8lZ1VIHDZcIYXQX41INBEbqGLZFzofDwJzpZPx4Qn91XkVGdsF2U")

(define generate-token-test-group
  (test-group "generate-token"
              (test-equal "works properly with correct details" #t
                          (let* ((get-owner-details get-owner-details)
                                 (t (generate-token #:encryption-key
                                                    some-valid-uuid
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
              (test-equal "works properly with valid token" #t
                          (let* ((d (decrypt-token #:encryption-key
                                                   some-valid-uuid
                                                   #:token some-valid-token)))
                            (display (format #f "\ndecoded token: ~s\n" d))
                            (and (not (equal? #f d))
                                 (not (equal? "" d))
                                 (not (equal? '() d))
                                 (equal? (assoc-ref d
                                                    'token-created-at)
                                         1749673042)
                                 (equal? (assoc-ref d
                                                    'owner-email)
                                  "hus1ktghpbqm3m7ll9w9aywhek7c96178nmr"))))))

(define garble-ungarble-string-test-group
  (test-group "garble-ungarble"
              (test-equal "dlrow olleh"
                          (string-garble "hello world"))
              (test-equal "hello world"
                          (string-ungarble (string-garble "hello world")))
              (let ((some-random-string (generate-random-string 128)))
                (test-equal some-random-string
                            (string-ungarble (string-garble some-random-string))))))

(define-test test-bewaking generate-token-test-group
             garble-ungarble-string-test-group)
