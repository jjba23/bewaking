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

(set! *random-state* (random-state-from-platform))

(define char-pool
  (string->list "abcdefghijklmnopqrstuvwxyz0123456789"))

(define (get-random-char)
  (list-ref char-pool (random (length char-pool))))

(define (generate-random-string length)
  (list->string
   (let loop ((count 0) (chars '()))
     (if (= count length)
         (reverse chars)
         (loop (+ count 1) (cons (get-random-char) chars))))))

(define generate-token-test-group
  (test-group "generate-token"
              (test-equal "works properly with correct details" #t
                          (let* ((encryption-key (generate-string-uuid))
                                 (get-owner-details (lambda ()
                                                     `((id unquote
                                                           (generate-string-uuid))
                                                       (email unquote (generate-random-string 36))
                                                       (name unquote (generate-random-string 12))
                                                       (permissions unquote (list
                                                                             (string->symbol (generate-random-string 16))
                                                                             (string->symbol (generate-random-string 16))
                                                                             (string->symbol (generate-random-string 16)))))))
                                 (t (generate-token #:encryption-key
                                                    encryption-key
                                                    #:get-owner-details
                                                    get-owner-details)))
                            (display (format #f "\nowner-details: ~s\n" (get-owner-details)))
                            (display (format #f "\ngenerate-token: ~a\n" t))
                            (and (not (equal? #f t))
                                 (not (equal? "" t))
                                 (not (equal? '() t)))))))

(define-test test-bewaking generate-token-test-group)
