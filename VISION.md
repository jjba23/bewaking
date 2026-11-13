# Vision

Bewaking is a Guile library for the part of a web application that decides who
somebody is and what they may do: it seals a payload under two keys, wraps it in a
versioned envelope, and hands back a string that travels in a cookie or a header.
The interesting question it answers is not "how do I encrypt this" but "how do I
know, months later, on a machine I no longer administer, that this string is
mine, unmodified, unexpired and about the person it claims?" This document is
about where that answer should go next.

## Where bewaking is today

The library is about 3,400 lines of Guile in four modules — `crypto.scm` for the
primitives, `bewaking.scm` for tokens, objects and envelopes, `password.scm` for
strength and storage, `cli.scm` for the command line — behind ten Org documents
totalling roughly 1,900 lines and five unit specs under `test/veritas/unit/`.

What exists, concretely:

- **Every primitive runs in-process** through libgcrypt: Base16 and Base64,
  HMAC-SHA256, PBKDF2-HMAC-SHA256, Argon2id, AES-256-CBC in the exact payload layout
  of `openssl enc -aes256 -pbkdf2`, and AES-256-GCM. The module used to shell out to
  `openssl`, `xxd` and `base64`; it now spawns nothing, interpolates nothing into a
  shell, and never puts a payload on a command line.
- **Two keys, two jobs.** The `encryption-key` provides confidentiality, the
  `signing-key` provides authenticity, and the outer seal is AES-256-GCM whose tag
  covers the header as well as the body — so the expiry cannot be edited into the
  future without the parcel refusing to open.
- **One envelope format, `BWK3`.** It is the only shape written and the only shape
  read: `BWK3.<key-id>.<created-at>.<expires-at>.<body>`. An earlier bare Base16
  token, an older format version, or arbitrary text is refused rather than guessed
  at.
- **Rotation metadata that is already usable.** `key-id` selects an entry in a
  keyring alist with optional `not-before`/`not-after` windows; a refusal is
  deliberately unspecific (unknown key, retired key, wrong key and tampering are
  one answer) except for expiry, which is only reachable once the tag has proved
  the parcel genuine. `bewaking token inspect` prints that metadata with no key at
  all.
- **The key-derivation choice travels with the data.** A body records whether it
  was sealed with PBKDF2 or Argon2id and with which parameters, so opening needs no
  matching option; `argon2id-available?` probes libgcrypt rather than assuming a
  version.
- **Payloads are Scheme data**, parsed with `read` and never `eval`, with an ACL
  vocabulary alongside: `has-needed-permissions?`, `is-token-expired?`,
  `token-remaining-seconds`, `token-valid?`.
- **Passwords**: entropy and strength scoring with a common-password list that caps
  the score at zero, generation from libgcrypt's CSPRNG, and Argon2id PHC storage
  with verification.

Two decisions constrain what comes next. The first is that the format is
**closed**: one version, one body layout, no algorithm negotiation, no legacy
parser to keep alive. That is why it is safe, and it is also why every future
format change costs a version tag rather than a flag. The second is that the
**garbling step is obfuscation, not cryptography** — the security comes from the
two keys, and `docs/security.org` says as much about what publishing the source
gives an attacker. Anything this document proposes has to add to the keys, not to
the obfuscation.

## The vision

1. **A bewaking token is verifiable outside Guile.** A published wire
   specification and a file of known-answer vectors mean a Rust or Go service
   sitting in front of a Guile backend can agree about what a token says, without
   reimplementing the pipeline by reading the source.

2. **Rotation is routine rather than an incident.** A deployment holds a keyring,
   re-seals the bodies it still needs under a new key id in one command, and gets a
   report of what remains on a retired key — instead of every application writing
   its own migration.

3. **Every default is a measurement.** The PBKDF2 and Argon2id parameters ship with
   published timings on named hardware, and a release that changes them says by how
   much and why.

4. **Password storage keeps pace with itself.** Verification reports that a stored
   hash used weaker parameters than today's default, so an application can rehash on
   the next successful login rather than carrying a 2026 cost model into 2031.

5. **Statelessness has an escape hatch.** A session can be revoked before it
   expires, without turning every verification into a database read, and the
   trade-off is a documented design decision rather than an omission.

## Features that are in scope and not built yet

- **Known-answer test vectors.** `seal-envelope` already takes a `random-source`
  whose docstring names its purpose: reproducing an envelope exactly, "in a test
  vector, or a compatibility check". What is missing is the file. The hard part is
  that a vector has to pin the KDF, its parameters and both keys, or it proves
  nothing about the pipeline.
- **Rehash on verify.** The parameters are in the PHC string and
  `verify-password` reads them. The hard part is the interface: the answer has to
  carry "this hash is below today's cost" without turning a verification into a
  policy engine, and without a caller silently accepting a weak hash as current.
- **Re-sealing for rotation.** Key ids, keyring windows and `open-envelope` are
  there; re-sealing is not. The hard part is that re-sealing needs the plaintext,
  so it is a read-then-write over every stored token — which means a report of what
  is still on a retired key matters more than the re-seal itself.
- **Typed conditions.** The crypto module exposes `call-with-error-handler` and
  `condition-message`, so callers distinguish expiry from tampering by matching text
  today; the hard part is a hierarchy that keeps refusals indistinguishable.
- **Middleware.** `docs/web.org` explains how to layer a cookie session and a header
  token over the API by hand. The hard part is that a middleware module has to choose
  an account model, and this library has deliberately never had one.
- **Revocation.** Both `docs/security.org` and `docs/web.org` discuss it; the code
  has `expires-at` and nothing else. The hard part is the cost curve: a denylist read
  per request gives up the property that makes a token cheap to check.

## New features that would be worth having

- **`bewaking keygen`.** The documentation suggests a UUID as a key, which is 122
  bits of a shape designed for uniqueness rather than for secrets. A generator that
  emits 32 random bytes in a printable form, refuses to print to a log, and can write
  a file with the right permissions would improve every deployment that follows the
  quick start.
- **`bewaking kdf calibrate`.** The CLI documentation already quotes the numbers
  (64 MiB with three passes is around 90 ms per derivation, and a token derives
  twice). A command that measures this machine and prints recommended parameters
  would make those numbers current rather than anecdotal.
- **`token inspect --verify`.** Inspecting metadata without a key is genuinely
  useful for operations; a variant that checks a token against a keyring and
  answers only "valid until Tuesday, key 2026a" — never the payload — would make
  the same page safe to run in production.
- **A sealed file format for configuration.** `encrypt-object` and `seal-envelope`
  already seal any datum; a small documented convention for an on-disk sealed file
  (header, body, no trailing-newline games) would let deployments keep credentials
  the way they already keep them.
- **A k-anonymity breach-list check for `password strength`** (speculative): an
  optional, explicitly networked check against a ranges API, off by default. Useful,
  and a genuine dependency on somebody else's service, which is why it stays
  speculative. Threshold sealing — splitting a key so that sealing needs two
  custodians — is speculative for a different reason: elegant, and of no interest to
  the deployments using this today.

## Contributions that would move the needle

1. **The wire specification and the vectors.** A document plus a small vector file
   is the highest value per hour here: it converts the code into a format, and a
   format is what another language can implement. Everything else gets easier after.
2. **Rehash on verify.** Small, self-contained, security-relevant, and testable
   against the existing password spec.
3. **Typed conditions.** A handful of `define-condition-type` forms and one rule —
   keep refusals indistinguishable, keep expiry distinct — improves every caller.
4. **`kdf calibrate` and published numbers.** Cheap, and it is the difference
   between a default defended by convention and one defended by measurement.
5. **Rearguard work on the key advice:** `keygen`, keyring management in the CLI,
   and a quick start that no longer suggests a UUID as a secret.
6. **Revocation.** The design note is worth more than the patch: options, cost, and
   what it does to the stateless property, decided in the open.

## Compared to related projects

| Project | What it is | Where bewaking differs |
| --- | --- | --- |
| PASETO | A versioned, purpose-separated token format with explicit protocol versions and cross-language implementations | `BWK3` has one version, no purpose field and no algorithm field; PASETO is the model for what bewaking's format could become once vectors exist |
| JWT / JOSE | JSON claims signed (JWS) or encrypted (JWE), with the algorithm chosen per token in a header | A JWS's claims are readable by anyone holding it, and its `alg` is attacker-steerable if a verifier trusts it; bewaking encrypts by default and has no algorithm to negotiate |
| Fernet (Python `cryptography`) | A single-key, versioned token: AES-128-CBC plus HMAC-SHA256 with a timestamp, implemented in many languages | One key, no expiry semantics, 128-bit AES; bewaking separates encryption from signing, uses AES-256-GCM, and the expiry is inside the tag |
| `itsdangerous` | Signed and encrypted serialisation for framework cookies | A serialiser with no envelope version, no key ring and no permission vocabulary; bewaking carries the ACL and answers `has-needed-permissions?` |
| libsodium (`secretbox`, sealed boxes) | Small, high-level, hard-to-misuse AEAD primitives | A primitive library rather than a token; bewaking is the token, the ACL, the password module and the CLI on top of libgcrypt |
| `argon2` / `passlib` | Password hashing tools with several algorithms, parameter guidance and rehash conventions | Bewaking hashes and verifies in-process with Argon2id PHC and also scores and generates; the others have wider algorithm coverage and the ecosystem to go with it |

What the others do that bewaking could still add is discipline made portable. PASETO
shows what purposes and published vectors buy: implementations in a dozen languages
that agree. Fernet shows the value of a single string every ecosystem can parse.
JOSE's key-set discovery is a rotation story that scales past one deployment, and
`passlib` established the rehash-on-login convention item four asks for.

Where bewaking is ahead and should stay ahead: encryption is the default and not an
option; the expiry is authenticated rather than merely present; there is no
algorithm field for an attacker to steer, because there is no negotiation; two keys
mean a leaked signing key decrypts nothing and a leaked encryption key mints
nothing; nothing reaches a shell; and the payload is Scheme data that `read` cannot
execute. Those properties are the product, and none of them can be traded for
interoperability.

## In the long run

The first bet is **the format over the library**. If the wire format is specified
and vectors exist, anyone can write a verifier, and bewaking's future stops
depending on Guile being chosen by the other side. If it is not, this stays a
good library for one ecosystem.

The second is **measurement over convention**. Cryptographic defaults age: what costs
90 ms in 2026 costs 30 ms on the laptop of 2029, and a project that publishes its
numbers can move them while one that quotes RFCs cannot tell when it has fallen
behind.

The third is **staying a library**. Bewaking is not an identity provider and should
not become one: no OpenID Connect, no user directory, no hosted service, because the
moment it owns accounts it inherits a threat model it has no staff to hold.

## What would make this document wrong

If a de-facto standard token format wins the ecosystem outright, item one becomes
"implement that" rather than "specify this", and the interesting work moves to
migration. If browsers make a cookie-based session unnecessary, the revocation item
loses its urgency but not its point. Neither changes the underlying bet: the keys are
the only secret, and everything else can be read, tested and reimplemented.

*A vision describes intent, not commitments: nothing here is promised for a
release, and the speculative items say so.*
