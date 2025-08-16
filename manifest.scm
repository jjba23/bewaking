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

(use-modules (guix packages)
             (gnu)
             (guix utils)
             (guix git-download)
             (guix download)
             (gnu packages guile)
             (gnu packages gnupg)
             (gnu packages guile)
             (gnu packages guile-xyz)
             (gnu packages pkg-config)
             (guix build-system guile)
             (gnu packages linux)
             (gnu packages compression)
             (gnu packages vim)
             (gnu packages tls)
             (gnu packages texinfo)
             (gnu packages autotools)
             ((guix licenses)
              #:prefix license:))

(define-public guile-veritas
  (package
    (name "guile-veritas")
    (version "0.1.8")
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://codeberg.org/jjba23/veritas.git")
             (commit (string-append "v" version))))
       (file-name (git-file-name name version))
       (sha256
        (base32 "0yg9qqwlln6y9ay1yljxq4x35il5bz7fl7j9nz5dygvdfffqs1v0"))))
    (build-system guile-build-system)
    (arguments
     (list
      #:source-directory "src"))
    (native-inputs (list guile-3.0))
    (propagated-inputs (list guile-fibers guile-json-4))
    (home-page "https://codeberg.org/jjba23/veritas")
    (synopsis "Testing framework for Guile")
    (description
     "Veritas is a testing framework for Guile with an @acronym{EDSL,
embedded domain specific language} to define test suites.  Emphasis is placed
on legibility and maintainability of tests.  Veritas shuffles tests and
runs them concurrently by default to ensure robust testing practices.")
    (license license:lgpl3+)))

(define-public guile-uuid
  (package
    (name "guile-uuid")
    (version "0.9.0")
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://codeberg.org/elb/guile-uuid.git")
             (commit (string-append "v" version))))
       (file-name (git-file-name name version))
       (sha256
        (base32 "0g508aajkyi513wbhm1rhs03ilnb701lwlrvppkmc0vynydlk9ws"))))
    (build-system guile-build-system)
    (native-inputs (list guile-3.0 guile-gcrypt))
    (home-page "https://codeberg.org/elb/guile-uuid")
    (synopsis "UUID generation and manipulation library for Guile Scheme")
    (description
     "This package implements RFC 9562 UUIDs, and can generate versions
1 and 3–8 from that specification. It also provides parsing for UUIDs in
standard hex-and-dash format of any variant and version. Simple routines for converting
between binary and hex-and-dash string UUIDs are included.")
    (license license:gpl3+)))

(packages->manifest (list (specification->package "make") guile-next
                          guile-veritas
                          guile-gcrypt guile-uuid guile-ares-rs
                          guile-documenta
                          texinfo
                          openssl
                          xxd))


