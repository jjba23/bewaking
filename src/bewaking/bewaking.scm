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
  #:use-module (uuid generate)
  #:export (issue-token))

(define* (issue-token #:key user-details-provider
                      (token-valid-seconds (* 60 60 48)))
  (let* ((token-id (generate-string-uuid))
         (now (current-time))
         (user-details (user-details-provider))
         (token-data `((token-type . bewaking-token)
                       (token-id unquote token-id)
                       (token-created-at unquote now)
                       (token-expires-at unquote (+ now token-valid-seconds))
                       (user-id unquote (assoc-ref user-details 'id))
                       (user-email unquote (assoc-ref user-details 'email))
                       (user-name unquote (assoc-ref user-details 'name))
                       (user-permissions unquote (assoc-ref user-details 'permissions))))
         (token (with-output-to-string (lambda() (write token-data)))))
    token))

(issue-token #:user-details-provider (lambda() `((id . "f421188e-3ca2-4d55-a65c-0278cd3f77b1")
                                            (email . "jjbigorra@gmail.com")
                                            (name . "Joe")
                                            (permissions . (bewaking:write bewaking:read)))))


;; Every call made, we need to hit db and decrypt, which means a bit of performance hit, so we can cache this for 5 minutes for example, 
;; Once logged in, you get a token, you then use the token for every call, we cache auth oks for 5 minutes, we do not cache auth errs
;; After 5 min we will hit db again to check for permission.
;; This is separate from the token expiry time, which only when current-timestamp > token-expiry, then we need to log you out and you need to login again
 
;; Then we take that token data (in Lisp/Scheme) and serialize it to JSON, minify, base64 encode it, reverse it, encrypt with some cypher (use openssl?), base64 encode it
;; For decoding we base64 decode, decrypt it (use openssl?), reverse it, base64 decode it, and parse the JSON

