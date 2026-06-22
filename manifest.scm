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
             (gnu packages rust-apps)
             (gnu packages linux)
             (gnu packages compression)
             (gnu packages vim)
             (gnu packages tls)
             (gnu packages texinfo)
             (gnu packages autotools)
             ((guix licenses)
              #:prefix license:))

(packages->manifest (list guile-3.0-latest
                          guile-veritas
                          guile-gcrypt
                          guile-uuid
                          guile-ares-rs
                          guile-documenta
                          texinfo
                          watchexec
                          openssl
                          xxd))
