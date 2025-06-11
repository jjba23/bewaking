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
  "4PpaC4wojwRcDo3EjvOEadjEgWJdoS2rAnxxuiVdbGhdZZcLbQ0ezKIjsHv85EMTEDdP5DCbObjw/P4AMR2OZsiRvMNuOKxmt4Oy5SEqrErfs3vgTmmeKgZIGTtk5NAhBVFDhq417mS1Xrh4JFLI7aJzOxH0Ctbp960dM2f68ZwFgMqjnrcepl+ULy3SxzKr+j4Nett981lebRm8jOoZ1zO1PQtgYq1woGQot7eTovFkPNBjWwNN4k6mbpbt3On8bMZQ/tv6p9otuLFFsxMxbWc5wyvrjiAYxLOu61Tm+e1/NNrbiKP8ShWF2g5TNLONi9Uf3J8Dy8eaXAAOQlTBsthhzVRrY1jwiIM9m5u3/k8TJnVmdUH2hx0AxYapJzjCUZY5MCzEPqJJB/BsQ+YjZJOxEOfuB8H4OX87ZCYmmuKRQri+dkcDLOmjzHKwiV3XfqD9fvTqswRhRdvuwatC+f4M5ucFHtP7w+b2C8ZnXJpPBMjpDe1IGfu4/+JvqiCw0Wa1X4qtMKkVnVxs7e2rnsdsNqmxE1uBFVxvqQ1xiW/g16IgQEyZOtHEimxhDaFl4bG0ruhApLbbESHP2zl++fAwCXg7/gmxZ2mdNTo6lUHi21TFV4/muiHTyZJf//T340eU8Txs8JtJjhkmEo1+qW6tnaZHF3P/xyNAH8UqnQ8FBI54Z2sYuAliJxcxzySQp5DW8HJosFVsfJChNC1qyrfdDOQxZ3yAXTw0cUUp7F1D3vKk0dtKAyieetH+sJSfXGFbOCGeenjn9j1BjrkqIlcjsNyErsOrn7x76UL3SnkeEowAVPpZiSq4doLdJooWs9Plg+W/OYCxSLA3yDYoqAfmJSTawykJr77UofmfMa6rSgt7ooOxJ/1XkVGdsF2U")

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
