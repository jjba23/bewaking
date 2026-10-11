;; bewaking

;; Copyright © Josep Bigorra <jjbigorra@gmail.com>

;; bewaking is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; bewaking is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; Lesser GNU General Public License for more details.

;; You should have received a copy of the GNU Lesser General Public License
;; along with bewaking.  If not, see <https://www.gnu.org/licenses/>.

(define-module (veritas unit web-spec)
  #:use-module (veritas veritas)
  #:use-module (bewaking bewaking))

;; ====== Why this file exists ======
;;
;; The README's chapter "Using bewaking in a web application" documents a
;; stateless-session pattern: a sign-in that seals a token into a cookie, one
;; middleware helper that answers "who is this, and are they allowed?", routes
;; that refuse rather than half-admit, sealed links for state the server does
;; not want to store, key rotation, revocation and auditing.
;;
;; Documentation drifts. This file is that chapter, committed as a regression
;; test: the helpers below are the ones the chapter prints, the requests and
;; responses are the framework-independent parts of the Artanis controllers in
;; the chapter, and the assertions are the behaviour the prose promises. If the
;; library changes in a way that would make the documented pattern wrong, this
;; spec fails, so the chapter cannot quietly become a lie.
;;
;; Nothing here imports a web framework: bewaking takes a string in and hands an
;; alist back, so a request is an alist and a response is an alist. Anything
;; offering "read a cookie or a header, set one" can use `authorized-payload'
;; unchanged.
;;
;; The test bodies consist of direct `assert-*' expressions, because veritas
;; only collects assertions that appear as direct expressions in a test body:
;; a shared, multi-step flow has to be a procedure that returns one value per
;; assertion. A flow hidden inside a `let' would have its first assertions
;; silently dropped, and a silently empty test is worse than no test.

;; ====== The keys and the cookie ======

(define encryption-key "952e0690-6c3b-4828-b191-961bf98d055c")
(define signing-key "503f5869-0a3c-4460-971f-5a88662de3fc")

(define cookie-name "x-bewaking-session")
(define week (* 7 24 3600))

;; A password check standing in for the application's own. The point of the
;; spec is what happens *after* this returns #t, not how it decides.
(define good-password "correct horse battery staple")

(define (valid-credentials? password)
  (string=? password good-password))

;; ====== 1. Sign-in: sealing a token into a cookie ======

(define* (issue-token #:key id email name permissions
                      (validity-seconds week)
                      (key-id default-key-id) keyring)
  "Turn a verified user into a token, exactly as the README's `issue-token'."
  (generate-token #:encryption-key encryption-key
                  #:signing-key signing-key
                  #:keyring keyring
                  #:key-id key-id
                  #:token-validity-seconds validity-seconds
                  #:get-owner-details
                  (lambda ()
                    `((id . ,id)
                      (email . ,email)
                      (name . ,name)
                      (permissions ,@permissions)))))

(define* (sign-in #:key password user-id email name permissions
                  (validity-seconds week)
                  (key-id default-key-id) keyring)
  "The framework-independent half of the README's sign-in: verify, seal, and
   describe the cookie to set. A failing password sets no cookie at all."
  (if (valid-credentials? password)
      (let ((token (issue-token #:id user-id #:email email #:name name
                                #:permissions permissions
                                #:validity-seconds validity-seconds
                                #:key-id key-id #:keyring keyring)))
        `((status . 302)
          (location . "/dashboard")
          (cookie . ((name . ,cookie-name)
                     (value . ,token)
                     (expires . ,validity-seconds)
                     (path . "/")
                     (secure . #t)
                     (http-only . #t)))))
      `((status . 401)
        (body . ((error . "invalid credentials"))))))

(define (sign-out)
  "Deleting the cookie is the whole sign-out: there is no server-side session
   to clean up."
  `((status . 302)
    (location . "/login")
    (cookie . ((name . ,cookie-name) (value . "") (expires . 0)))))

(define (status-of response) (assoc-ref response 'status))
(define (body-of response) (assoc-ref response 'body))
(define (response-cookie response)

  (assoc-ref response 'cookie))

(define (cookie-token response)
  (let ((cookie (response-cookie response)))
    (and cookie (assoc-ref cookie 'value))))

(define* (a-session #:key (password good-password) (user-id "u-1")
                    (email "joe@example.com") (name "Joe")
                    (permissions '(read-only access-files))
                    (validity-seconds week))
  "A freshly minted session, so that no assertion can be perturbed by another
   one mutating shared state."
  (sign-in #:password password #:user-id user-id #:email email #:name name
           #:permissions permissions #:validity-seconds validity-seconds))

(define (session-token) (cookie-token (a-session)))

(define (cookie-field field)
  (assoc-ref (response-cookie (a-session)) field))

;; ====== 2. Protecting a route: one helper, one question ======

(define* (authorized-payload #:key token (needed '()) keyring)
  "Return the decrypted payload when the token is genuine, unexpired and
   carries every needed permission; otherwise #f. The README is explicit that
   `decrypt-token' catches everything and returns #f, so the result is tested
   *before* the payload is touched."
  (let ((payload (and (string? token)
                      (not (string-null? token))
                      (decrypt-token #:token token
                                     #:encryption-key encryption-key
                                     #:signing-key signing-key
                                     #:keyring keyring))))
    (and payload
         (token-valid? #:token payload)
         (has-needed-permissions? #:needed needed
                                  #:present (assoc-ref payload
                                                       'owner-permissions))
         payload)))

(define* (browser-route request #:key (needed '()) keyring
                        (handler (lambda (payload) payload)))
  "The GET/POST body of the README's controller: read the cookie, decide, then
   either run the handler or redirect to the login page."
  (let ((who (authorized-payload #:token (assoc-ref request 'cookie)
                                 #:needed needed
                                 #:keyring keyring)))
    (if who
        `((status . 200) (body . ,(handler who)))
        `((status . 302) (location . "/login")))))

(define* (api-route request #:key (needed '()) keyring)
  "The README's API controller: read a header instead of a cookie and answer
   with a status code, which suits clients with no cookie jar."
  (let ((who (authorized-payload #:token (assoc-ref request 'header)
                                 #:needed needed
                                 #:keyring keyring)))
    (if who
        `((status . 200)
          (body . ((owner-id . ,(assoc-ref who 'owner-id))
                   (required . ,(assoc-ref who 'owner-permissions)))))
        `((status . 401) (body . ((error . "authentication required")))))))

(define (browser-status token)
  (status-of (browser-route `((cookie . ,token)))))

(define (browser-status-for token needed)
  (status-of (browser-route `((cookie . ,token)) #:needed needed)))

(define (authorized-field field)
  (assoc-ref (body-of (browser-route `((cookie . ,(session-token))))) field))

;; One day, both in the cookie and in the envelope: the README's rule is that
;; the two lifetimes move together.
(define (one-day-cookie-field field)
  (assoc-ref (response-cookie (a-session #:validity-seconds (* 24 3600))) field))

(define (one-day-metadata-field field)
  (assoc-ref (audit (a-session #:validity-seconds (* 24 3600))) field))

;; A sign-in with a wrong password.
(define (refused-session) (a-session #:password "hunter2"))

;; A request that *claims* to be someone else next to a genuine session.
(define (identity-claiming-request)
  (body-of (browser-route `((cookie . ,(session-token))
                            (claim-user-id . "u-999")
                            (form . ((owner-id . "u-999")))))))

;; A payload whose lifetime is already over, deterministically.
(define (stale-token) (cookie-token (a-session #:validity-seconds -1)))

;; ====== 3. Sealed objects: stateless state that must not be tampered with ======

(define (sealed-reset-link user-id)
  "A `reset your password' link that expires in an hour, with no table row."
  (encrypt-object #:payload `((user . ,user-id) (action . reset-password))
                  #:encryption-key encryption-key
                  #:signing-key signing-key
                  #:ttl-seconds 3600))

(define (sealed-reset-link-expired-at timestamp)
  "The same link, with an explicit past expiry, so an expired link can be
   tested deterministically."
  (encrypt-object #:payload '((user . "u-1") (action . reset-password))
                  #:encryption-key encryption-key
                  #:signing-key signing-key
                  #:expires-at timestamp))

(define* (read-reset-link link #:key (now (current-time)))
  "The other half of the README's reset flow: #f once the hour is over, or if
   the link was edited in the mail client.

   The README spells this with `decrypt-object', which returns #f on any
   failure. `#:now' is used here so that the expiry can be tested without
   waiting an hour, and only `unsafe-decrypt-object' accepts that; catching its
   error and returning #f is the same contract the README documents."
  (catch #t
         (lambda ()
           (unsafe-decrypt-object #:object link
                                  #:encryption-key encryption-key
                                  #:signing-key signing-key
                                  #:now now))
         (lambda (key . args) #f)))

;; ====== 4. Keys, rotation and revocation ======

(define current-keyring
  '(("2026a" (encryption-key . "enc-2026a") (signing-key . "sig-2026a"))
    ("2025b" (encryption-key . "enc-2025b") (signing-key . "sig-2025b"))))

;; The keyring after `2025b' has been retired: the `not-after' window is how the
;; README says "log everyone out now".
(define retired-keyring
  '(("2026a" (encryption-key . "enc-2026a") (signing-key . "sig-2026a"))
    ("2025b" (encryption-key . "enc-2025b") (signing-key . "sig-2025b")
             (not-after . 1000))))

(define (keyring-session key-id)
  (issue-token #:id "u-1" #:email "joe@example.com" #:name "Joe"
               #:permissions '(reader)
               #:keyring current-keyring #:key-id key-id))

(define (opens-with-keyring? token keyring)
  (and (authorized-payload #:token token #:keyring keyring) #t))

;; ====== 5. Auditing ======

(define (audit response)
  "What the README says is safe to log: the envelope header, read with no keys
   at all. It is a claim, not a decision. A request with no session cookie has
   nothing to audit, and that is #f rather than an error."
  (let ((token (cookie-token response)))
    (and token (envelope-metadata #:sealed token))))

(define (session-metadata-field field)
  (assoc-ref (audit (a-session)) field))

(define (raises? thunk)
  (catch #t (lambda () (thunk) #f) (lambda args #t)))

(define (flip-char s index)
  "Return @var{s} with the character at @var{index} replaced by a different
   one, as an attacker editing a captured cookie would."
  (let* ((character (string-ref s index))
         (replacement (if (char=? character #\0) #\1 #\0)))
    (string-append (substring s 0 index)
                   (string replacement)
                   (substring s (+ index 1) (string-length s)))))

(define (tampered token)
  (flip-char token (quotient (string-length token) 2)))

;; ====== The session pattern ======

(define sign-in-suite
  (suite "Web chapter: sign-in seals a session into a cookie"
         (test "a verified user gets a sealed session cookie"
               (assert-equal #:expect 302 #:got (status-of (a-session))
                             #:name "sign-in redirects, as the README's controller does")
               (assert-equal #:expect "/dashboard"
                             #:got (assoc-ref (a-session) 'location)
                             #:name "the redirect target is the dashboard")
               (assert-true (string-prefix? "BWK3." (session-token))
                            #:name "the cookie value is a BWK3 envelope")
               (assert-equal #:expect cookie-name #:got (cookie-field 'name)
                             #:name "the cookie is named as documented")
               (assert-true (cookie-field 'http-only)
                            #:name "(a) HttpOnly puts the cookie out of reach of JavaScript")
               (assert-true (cookie-field 'secure)
                            #:name "(b) Secure keeps it off plain HTTP")
               (assert-equal #:expect "/" #:got (cookie-field 'path)
                             #:name "(c) path \"/\" applies the cookie to the whole site")
               (assert-equal #:expect week #:got (cookie-field 'expires)
                             #:name "(d) the cookie's lifetime matches #:token-validity-seconds"))
         (test "the cookie lifetime can be aligned with the token's"
               ;; The README's rule: a cookie that outlives its token only
               ;; annoys users with half-logged-in states. Here both are one day.
               (assert-equal #:expect (* 24 3600) #:got (one-day-cookie-field 'expires)
                             #:name "the requested lifetime is recorded in the cookie")
               (assert-true (integer? (one-day-metadata-field 'created-at))
                            #:name "the envelope is sealed now")
               (assert-false (one-day-metadata-field 'expires-at)
                             #:name "the payload lifetime is separate from the cookie's"))
         (test "bad credentials get no cookie at all"
               (assert-equal #:expect 401 #:got (status-of (refused-session))
                             #:name "a wrong password is a plain 401")
               (assert-false (response-cookie (refused-session))
                             #:name "no session is created for a failed sign-in")
               (assert-equal #:expect "invalid credentials"
                             #:got (assoc-ref (body-of (refused-session)) 'error)
                             #:name "the failure is reported, not swallowed"))))

(define protected-route-suite
  (suite "Web chapter: protecting a route"
         (test "the signed-in user is admitted"
               (assert-equal #:expect 200 #:got (browser-status (session-token))
                             #:name "the browser route runs the handler")
               (assert-equal #:expect "u-1" #:got (authorized-field 'owner-id)
                             #:name "the handler sees the owner id from the payload")
               (assert-equal #:expect "joe@example.com"
                             #:got (authorized-field 'owner-email)
                             #:name "the thunk's 'email' came back as 'owner-email'")
               (assert-equal #:expect "Joe" #:got (authorized-field 'owner-name)
                             #:name "and 'name' came back as 'owner-name'")
               (assert-equal #:expect '(read-only access-files)
                             #:got (authorized-field 'owner-permissions)
                             #:name "permissions travel inside the token")
               (assert-true (string? (authorized-field 'token-id))
                            #:name "the payload carries its own token id")
               (assert-true (integer? (authorized-field 'token-expires-at))
                            #:name "and its own payload expiry"))
         (test "the same session works as an API bearer token"
               (assert-equal #:expect 200
                             #:got (status-of (api-route `((header . ,(session-token)))
                                                         #:needed '(access-files)))
                             #:name "the API route admits the header token")
               (assert-equal #:expect "u-1"
                             #:got (assoc-ref (body-of
                                               (api-route `((header . ,(session-token)))))
                                              'owner-id)
                             #:name "the token identifies the caller without a database round-trip")
               (assert-equal #:expect '(read-only access-files)
                             #:got (assoc-ref (body-of
                                               (api-route `((header . ,(session-token)))))
                                              'required)
                             #:name "the granted permissions are what the token says"))
         (test "every failure mode is a refusal, never an admission"
               (assert-equal #:expect 302
                             #:got (status-of (browser-route '()))
                             #:name "a request with no cookie is redirected to /login")
               (assert-equal #:expect 302
                             #:got (browser-status "")
                             #:name "an empty cookie is refused")
               (assert-equal #:expect 302
                             #:got (browser-status (tampered (session-token)))
                             #:name "a tampered cookie is refused")
               (assert-equal #:expect 302
                             #:got (browser-status "BWK3.a.b.c.d")
                             #:name "a cookie that is not a real envelope is refused")
               (assert-equal #:expect 302
                             #:got (browser-status "not-a-token")
                             #:name "arbitrary text is refused")
               (assert-equal #:expect 200
                             #:got (browser-status (cookie-token (a-session
                                                                  #:user-id "u-2"
                                                                  #:email "x@example.com"
                                                                  #:name "X")))
                             #:name "a second user's genuine session is admitted, as that user")
               (assert-equal #:expect "u-2"
                             #:got (assoc-ref (body-of
                                               (browser-route
                                                `((cookie . ,(cookie-token
                                                              (a-session #:user-id "u-2"
                                                                         #:email "x@example.com"
                                                                         #:name "X"))))))
                                              'owner-id)
                             #:name "and it admits the *second* user, not the first")
               (assert-equal #:expect 302
                             #:got (status-of (browser-route
                                               `((cookie . ,(session-token)))
                                               #:keyring (list (car current-keyring))))
                             #:name "a keyring that cannot resolve the key id is refused"))
         (test "a permission that was never granted is refused on the server"
               (assert-equal #:expect 302
                             #:got (browser-status-for (session-token) '(artist:edit))
                             #:name "the browser route refuses a route the user may not use")
               (assert-equal #:expect 401
                             #:got (status-of (api-route `((header . ,(session-token)))
                                                         #:needed '(artist:edit)))
                             #:name "the API route answers 401 rather than 403-by-omission")
               (assert-false (authorized-payload #:token (session-token)
                                                 #:needed '(artist:edit))
                             #:name "the helper returns #f, not a partially authorized payload")
               (assert-true (and (authorized-payload #:token (session-token)
                                                     #:needed '(read-only))
                                 #t)
                            #:name "the permission the user does have is enough")
               (assert-true (and (authorized-payload #:token (session-token)) #t)
                            #:name "a route needing nothing is open to a valid session"))
         (test "the payload is the identity, not the request"
               ;; The checklist: never trust a client-supplied user id that
               ;; arrives next to a token. Here the request claims to be someone
               ;; else; the token decides.
               (assert-equal #:expect "u-1"
                             #:got (assoc-ref (identity-claiming-request) 'owner-id)
                             #:name "the owner id comes from the sealed payload")
               (assert-false (string=? "u-999" (assoc-ref (identity-claiming-request)
                                                          'owner-id))
                             #:name "a client-supplied user id is a hint, never the identity"))
         (test "an expired session is refused, and sign-out clears the cookie"
               ;; A negative lifetime makes a *deterministic* expired payload:
               ;; `token-expires-at' is already in the past when the route sees
               ;; it, so no assertion depends on how long the run takes.
               (assert-equal #:expect 302 #:got (browser-status (stale-token))
                             #:name "a token whose payload lifetime has passed is refused")
               (assert-false (authorized-payload #:token (stale-token))
                             #:name "and the helper returns #f for it")
               (assert-equal #:expect 302 #:got (status-of (sign-out))
                             #:name "sign-out redirects to the login page")
               (assert-equal #:expect "" #:got (cookie-token (sign-out))
                             #:name "sign-out deletes the cookie, the only cleanup there is")
               (assert-equal #:expect 0
                             #:got (assoc-ref (response-cookie (sign-out)) 'expires)
                             #:name "the deletion cookie expires immediately"))))

(define sealed-object-suite
  (suite "Web chapter: sealed objects as stateless state"
         (test "a password-reset link round-trips with no table row"
               (assert-true (string-prefix? "BWK3." (sealed-reset-link "u-1"))
                            #:name "the link is a sealed envelope")
               (assert-equal #:expect '((user . "u-1") (action . reset-password))
                             #:got (read-reset-link (sealed-reset-link "u-1"))
                             #:name "the state comes back as an ordinary alist")
               (assert-false (string-contains (sealed-reset-link "u-1") "u-1")
                             #:name "the user id is not readable in the link")
               (assert-true (integer? (assoc-ref (envelope-metadata
                                                  #:sealed (sealed-reset-link "u-1"))
                                                 'expires-at))
                            #:name "the hour-long lifetime is recorded in the header"))
         (test "an edited link is worth nothing"
               (assert-false (read-reset-link (tampered (sealed-reset-link "u-1")))
                             #:name "the link was edited in the mail client")
               (assert-false (read-reset-link "not-a-link")
                             #:name "and garbage is not a link either"))
         (test "the link answers only to the key that sealed it"
               ;; A reset link sealed for one deployment cannot be replayed
               ;; against another, because the keys differ.
               (assert-false (decrypt-object #:object (sealed-reset-link "u-1")
                                             #:encryption-key "another-encryption-key"
                                             #:signing-key "another-signing-key")
                             #:name "a link sealed elsewhere does not open here"))
         (test "an expired link is refused by the server, not by the client"
               (assert-equal #:expect '((user . "u-1") (action . reset-password))
                             #:got (read-reset-link
                                    (sealed-reset-link-expired-at 1000) #:now 500)
                             #:name "before the expiry the link opens")
               (assert-false (read-reset-link (sealed-reset-link-expired-at 1000)
                                              #:now 2000)
                             #:name "after the expiry the server refuses it")
               (assert-true (envelope-expired? #:sealed
                                               (sealed-reset-link-expired-at 1000)
                                               #:now 2000)
                            #:name "and the header says so, for the log"))
         (test "a cursor or half-finished form can be sealed the same way"
               ;; The README's other examples: pagination cursors and
               ;; multi-step form state, with the same guarantee.
               (assert-equal #:expect "page-3"
                             #:got (open-envelope
                                    #:sealed (seal-envelope #:plaintext "page-3"
                                                            #:encryption-key encryption-key
                                                            #:signing-key signing-key)
                                    #:encryption-key encryption-key
                                    #:signing-key signing-key)
                             #:name "a sealed cursor round-trips")
               (assert-true (raises? (lambda ()
                                       (open-envelope
                                        #:sealed (tampered
                                                  (seal-envelope
                                                   #:plaintext "page-3"
                                                   #:encryption-key encryption-key
                                                   #:signing-key signing-key))
                                        #:encryption-key encryption-key
                                        #:signing-key signing-key)))
                            #:name "a client cannot page anywhere it was not sent"))))

(define rotation-suite
  (suite "Web chapter: keys, rotation and revocation"
         (test "rotation needs no downtime and no forced logout"
               (assert-true (string-prefix? "BWK3.2025b." (keyring-session "2025b"))
                            #:name "the key id is embedded in the envelope")
               (assert-true (string-prefix? "BWK3.2026a." (keyring-session "2026a"))
                            #:name "new logins are sealed with the current key")
               (assert-true (opens-with-keyring? (keyring-session "2025b")
                                                 current-keyring)
                            #:name "an old token still opens: nothing to migrate")
               (assert-true (opens-with-keyring? (keyring-session "2026a")
                                                 current-keyring)
                            #:name "and so does a new one"))
         (test "retiring a key logs every session sealed with it out at once"
               (assert-false (authorized-payload #:token (keyring-session "2025b")
                                                 #:keyring retired-keyring)
                             #:name "the retired key id stops opening sessions")
               (assert-true (opens-with-keyring? (keyring-session "2026a")
                                                 retired-keyring)
                            #:name "the current key keeps working"))
         (test "keys stay secret and distinct, which is the whole requirement"
               ;; The README's checklist. Both properties are visible in the
               ;; data: the token carries the key id, never the key, and a
               ;; session sealed with the wrong pair does not open.
               (assert-false (string-contains (session-token) encryption-key)
                             #:name "the encryption key does not appear in the token")
               (assert-false (string-contains (session-token) signing-key)
                             #:name "nor does the signing key")
               (assert-false (decrypt-token #:token (session-token)
                                            #:encryption-key signing-key
                                            #:signing-key encryption-key)
                             #:name "swapping the two keys does not open the session"))))

(define audit-suite
  (suite "Web chapter: auditing what is safe to log"
         (test "the envelope header is readable with no keys at all"
               (assert-equal #:expect "BWK3" #:got (session-metadata-field 'version)
                             #:name "the version is reported for the log")
               (assert-equal #:expect default-key-id
                             #:got (session-metadata-field 'key-id)
                             #:name "the key id is reported, which is what rotation is keyed on")
               (assert-true (integer? (session-metadata-field 'created-at))
                            #:name "the creation time is reported")
               (assert-false (envelope-expired? #:sealed (session-token))
                             #:name "a fresh session is not expired")
               (assert-false (string-contains (format #f "~s" (audit (a-session)))
                                              encryption-key)
                             #:name "the audit output carries no key material")
               (assert-false (string-contains (format #f "~s" (audit (a-session)))
                                              signing-key)
                             #:name "not the encryption key and not the signing key either"))
         (test "an expiry is reported as a time, and its absence as nothing"
               (assert-false (session-metadata-field 'expires-at)
                             #:name "the audit reports no envelope expiry by default")
               (assert-true (integer? (assoc-ref (envelope-metadata
                                                  #:sealed (seal-envelope
                                                            #:plaintext "x"
                                                            #:encryption-key encryption-key
                                                            #:signing-key signing-key
                                                            #:ttl-seconds 3600))
                                                 'expires-at))
                            #:name "a token sealed with a TTL records its expiry")
               (assert-false (envelope-expired? #:sealed (seal-envelope
                                                          #:plaintext "x"
                                                          #:encryption-key encryption-key
                                                          #:signing-key signing-key
                                                          #:ttl-seconds 3600))
                             #:name "and the audit helper agrees it is live"))
         (test "auditing garbage is #f, not an exception"
               (assert-false (audit '((cookie . ((value . "not-a-token")))))
                             #:name "an unparseable cookie yields no metadata")
               (assert-false (audit '())
                             #:name "a missing cookie yields no metadata")
               (assert-false (envelope-metadata #:sealed "BWK3.not.a.header")
                             #:name "a malformed BWK3 value yields no metadata"))))

(define (spec)
  (veritas-run sign-in-suite protected-route-suite sealed-object-suite
               rotation-suite audit-suite))
