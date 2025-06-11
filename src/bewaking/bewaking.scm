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

(define-module (bewaking bewaking)
  #:export (issue-token))

(define*)

;; Create secure tokens, token data itself consists of:

;; {
;;   "token-id": ,
;;   "token-created-at": EPOCH SECONDS,
;;   "token-expires-at": ,
;;   "user-id": ,
;;   "user-email": "jjbigorra@gmail.com",
;;   "user-name": "Joe"
;; }

;; Every call made, we need to hit db and decrypt, which means a bit of performance hit, so we can cache this for 5 minutes for example, 
;; Once logged in, you get a token, you then use the token for every call, we cache auth oks for 5 minutes, we do not cache auth errs
;; After 5 min we will hit db again to check for permission.
;; This is separate from the token expiry time, which only when current-timestamp > token-expiry, then we need to log you out and you need to login again
 
;; Then we take that token data (in Lisp/Scheme) and serialize it to JSON, minify, base64 encode it, reverse it, encrypt with some cypher (use openssl?), base64 encode it
;; For decoding we base64 decode, decrypt it (use openssl?), reverse it, base64 decode it, and parse the JSON

