;; bewaking
;;
;; SPDX-License-Identifier: MIT
;; Copyright © Josep Bigorra <jjbigorra@gmail.com>

(define-module (bewaking cli)
  #:use-module (ice-9 format)
  #:use-module (ice-9 rdelim)
  #:use-module (ice-9 textual-ports)
  #:use-module (srfi srfi-11)
  #:use-module (bewaking bewaking)
  #:use-module (bewaking password)
  #:export (run usage))

(define program-name "bewaking")

(define default-validity-seconds "604800")

;; ====== Usage text ======

(define usage
  "bewaking — encrypted tokens, sealed objects and password tools

Usage:
  bewaking token generate   [options]
  bewaking token decrypt    [options]
  bewaking token inspect    [options]
  bewaking object encrypt   [options]
  bewaking object decrypt   [options]
  bewaking password strength [PASSWORD]
  bewaking password generate [options]
  bewaking help

Keys (required for token/object commands, unless --keyring is given):
  --encryption-key KEY          inner AES-256 key (1st seal)
  --encryption-key-file FILE    read the inner key from FILE
  --signing-key KEY             outer AES-256 key (2nd seal)
  --signing-key-file FILE       read the outer key from FILE
  --keyring FILE                Scheme alist of key-id -> keys, for rotation
  --key-id LABEL                key id embedded when sealing (default \"default\")
  Environment fallbacks: BEWAKING_ENCRYPTION_KEY, BEWAKING_SIGNING_KEY

Rotation metadata (recorded in the sealed header and covered by the cipher tag):
  --ttl-seconds N               seal data that expires N seconds from now
  --expires-at TS               seal data that expires at an absolute Unix time
  --max-age-seconds N           refuse data sealed longer ago than N seconds
  --allow-expired               open expired data anyway (audit/recovery only)

Key derivation (sealing only; opening reads it back from the data itself):
  --kdf NAME                    pbkdf2 (default) or argon2id
  --kdf-memory-kib N            Argon2id memory cost in KiB (default 65536)
  --kdf-iterations N            Argon2id passes (default 3)
  --kdf-parallelism N           Argon2id lanes (default 1)
  Argon2id requires libgcrypt 1.11 or newer. The cost is per AES layer and a
  token has two, so sealing and opening each derive twice: 64 MiB with 3
  passes is around 90 ms per derivation, 8 MiB with 1 pass around 3 ms.
  PBKDF2 takes no parameters, because the OpenSSL-compatible format it
  produces has nowhere to record them.

A keyring file has the shape (not-before/not-after are optional rotation
windows; using a key outside its window is refused):
  ((\"2026a\" (encryption-key . \"e1\") (signing-key . \"s1\"))
   (\"2025b\" (encryption-key . \"e0\") (signing-key . \"s0\")
            (not-after . 1790000000)))

token generate:
  --owner-details FILE          owner alist read from FILE (alternative below)
  --owner-id ID                 owner id (required unless --owner-details)
  --owner-email EMAIL           owner email
  --owner-name NAME             owner name
  --permissions a,b,c           comma-separated permission symbols
  --validity-seconds N          token lifetime (default 604800)

token decrypt:
  --token TOKEN                 token string
  --token-file FILE             read the token from FILE

token inspect:
  --token TOKEN | --token-file FILE
                                print the envelope metadata (version, key id,
                                created-at, expiry) without needing any key

object encrypt / object decrypt:
  --input FILE                  read the payload/sealed string from FILE
                                (default: standard input)

password strength:
  PASSWORD (positional) or one line on standard input

password generate:
  --length N                    password length (default 24)
  --no-symbols                  exclude symbol characters

Examples:
  bewaking token generate --owner-id 42 --owner-name Joe \\
      --permissions read,write --encryption-key \"$K1\" --signing-key \"$K2\"
  bewaking token decrypt --token \"$TOKEN\" \\
      --encryption-key \"$K1\" --signing-key \"$K2\"
  echo '((name . Joe) (score . 7))' | bewaking object encrypt \\
      --encryption-key \"$K1\" --signing-key \"$K2\"
  bewaking token generate --owner-id 42 --kdf argon2id \\
      --kdf-memory-kib 8192 --encryption-key \"$K1\" --signing-key \"$K2\"
  bewaking password generate --length 32
")

;; ====== Small helpers ======

(define (cli-error fmt . args)
  "Abort the current command with a formatted, user-facing message."
  (throw 'cli-error (apply format #f fmt args)))

(define (index-of str ch)
  "Return the index of the first occurrence of @var{ch} in @var{str}, or #f."
  (let loop ((i 0))
    (cond ((= i (string-length str)) #f)
          ((char=? (string-ref str i) ch) i)
          (else (loop (+ i 1))))))

(define (opt options name)
  "Return the value of option @var{name} in @var{options}, or #f."
  (let ((entry (assoc name options)))
    (and entry (cdr entry))))

(define (parse-options args)
  "Parse @var{args} into two values: an association list of option name strings
   to value strings, and the list of positional arguments.

   Both ~--name=value~ and ~--name value~ are accepted. A bare ~--name~ is stored
   with the value \"true\". A bare ~--~ ends option parsing."
  (let loop ((rest args) (options '()) (positionals '()))
    (cond ((null? rest) (values (reverse options) (reverse positionals)))
          ((equal? (car rest) "--")
           (values (reverse options)
                   (append (reverse positionals) (cdr rest))))
          ((string-prefix? "--" (car rest))
           (let* ((arg (substring (car rest) 2 (string-length (car rest))))
                  (eq (index-of arg #\=)))
             (if eq
                 (loop (cdr rest)
                       (acons (substring arg 0 eq)
                              (substring arg (+ eq 1) (string-length arg))
                              options)
                       positionals)
                 (if (and (pair? (cdr rest))
                          (not (string-prefix? "--" (cadr rest))))
                     (loop (cddr rest) (acons arg (cadr rest) options)
                           positionals)
                     (loop (cdr rest) (acons arg "true" options)
                           positionals)))))
          (else (loop (cdr rest) options (cons (car rest) positionals))))))

(define (read-file file)
  "Read the entire contents of @var{file} as a string."
  (catch #t
         (lambda () (call-with-input-file file get-string-all))
         (lambda (key . args)
           (cli-error "cannot read file '~a'" file))))

(define (read-file-datum file)
  "Read a single Scheme datum from @var{file}."
  (catch #t
         (lambda () (call-with-input-file file read))
         (lambda (key . args)
           (cli-error "cannot read Scheme datum from '~a'" file))))

(define (read-stdin-string)
  "Read all of standard input as a string."
  (get-string-all (current-input-port)))

(define (resolve-secret options direct-opt file-opt env-var label)
  "Resolve a secret from, in order: the direct option, a file, an environment
   variable. Returns #f when none is provided."
  (let ((direct (opt options direct-opt))
        (file (opt options file-opt))
        (env (getenv env-var)))
    (cond (direct direct)
          (file (string-trim-right (read-file file)))
          (env env)
          (else #f))))

(define (keyring-option options)
  "Read the --keyring FILE, a Scheme alist of key-id -> key entry, if given."
  (let ((file (opt options "keyring")))
    (if file
        (let ((datum (read-file-datum file)))
          (unless (list? datum)
            (cli-error "--keyring FILE must contain a Scheme alist"))
          datum)
        #f)))

(define (key-id-option options)
  "Return the key id to embed when sealing, defaulting to the library default."
  (or (opt options "key-id") default-key-id))

(define (require-keys options)
  "Return four values: the encryption key, signing key, keyring and key id.

   Aborts with a helpful message when neither explicit keys nor a keyring are
   available."
  (let ((encryption-key (resolve-secret options "encryption-key"
                                        "encryption-key-file"
                                        "BEWAKING_ENCRYPTION_KEY"
                                        "encryption key"))
        (signing-key (resolve-secret options "signing-key" "signing-key-file"
                                     "BEWAKING_SIGNING_KEY" "signing key"))
        (keyring (keyring-option options)))
    (unless (or keyring encryption-key)
      (cli-error
       "missing encryption key (use --encryption-key, --encryption-key-file, --keyring or BEWAKING_ENCRYPTION_KEY)"))
    (unless (or keyring signing-key)
      (cli-error
       "missing signing key (use --signing-key, --signing-key-file, --keyring or BEWAKING_SIGNING_KEY)"))
    (values encryption-key signing-key keyring (key-id-option options))))

(define (parse-integer-option value name)
  "Parse @var{value} as an integer option value, aborting with a helpful message
   when it is not an integer."
  (let ((number (string->number value)))
    (unless (and number (integer? number))
      (cli-error "~a must be an integer" name))
    number))

(define (expiry-args options)
  "Return two values for sealing: the envelope TTL in seconds and the explicit
   expiry timestamp, both #f when the corresponding option is absent."
  (let ((ttl (opt options "ttl-seconds"))
        (expires (opt options "expires-at")))
    (when (and ttl expires)
      (cli-error
       "--ttl-seconds and --expires-at are mutually exclusive"))
    (values (if ttl (parse-integer-option ttl "--ttl-seconds") #f)
            (if expires
                (parse-integer-option expires "--expires-at")
                #f))))

(define (open-policy-args options)
  "Return two values for opening: whether to enforce expiry (the default, turned
   off by --allow-expired) and the optional --max-age-seconds rotation policy."
  (let ((max-age (opt options "max-age-seconds")))
    (values (not (opt options "allow-expired"))
            (if max-age
                (parse-integer-option max-age "--max-age-seconds")
                #f))))

(define (kdf-option options)
  "Return the key-derivation specification selected by the --kdf options.

   --kdf names the function and the three parameter options are optional
   overrides. Without --kdf the library default is used, and the parameter
   options are then refused rather than silently ignored. The library itself
   validates names and ranges, so a typo is reported with its own message."
  (let ((name (opt options "kdf"))
        (memory (opt options "kdf-memory-kib"))
        (iterations (opt options "kdf-iterations"))
        (parallelism (opt options "kdf-parallelism")))
    (cond
     ((not name)
      (when (or memory iterations parallelism)
        (cli-error
         "--kdf-memory-kib, --kdf-iterations and --kdf-parallelism require --kdf argon2id"))
      default-kdf)
     (else
      (append (list (cons 'kdf (string->symbol name)))
              (if memory
                  (list (cons 'memory-kib
                              (parse-integer-option memory "--kdf-memory-kib")))
                  '())
              (if iterations
                  (list (cons 'iterations
                              (parse-integer-option iterations "--kdf-iterations")))
                  '())
              (if parallelism
                  (list (cons 'parallelism
                              (parse-integer-option parallelism "--kdf-parallelism")))
                  '()))))))

(define (parse-permissions value)
  "Split a comma-separated permission string into a list of symbols."
  (if (or (not value) (string-null? value))
      '()
      (map string->symbol (string-split value #\,))))

(define (exception-message key args)
  "Best-effort human-readable message from an exception caught as
   @var{key} and @var{args}.

   Guile reports `error` calls through a data list holding the original message
   and its arguments; where that appears differs between Guile versions, so the
   list is located structurally and formatted. Falls back to the exception key."
  (let* ((data (let loop ((rest args))
                 (cond ((null? rest) #f)
                       ((and (pair? (car rest)) (string? (caar rest)))
                        (car rest))
                       (else (loop (cdr rest))))))
         (strings (let loop ((rest args) (found '()))
                    (cond ((null? rest) found)
                          ((string? (car rest))
                           (loop (cdr rest) (cons (car rest) found)))
                          (else (loop (cdr rest) found))))))
    (cond (data (catch #t
                        (lambda () (apply format #f data))
                        (lambda (k . a) (car data))))
          ((pair? strings) (car strings))
          (else (format #f "~a" key)))))

(define last-attempt-error #f)

(define (attempt thunk)
  "Run @var{thunk} and return its value, or #f if it raises. The library's own
   message is remembered in `last-attempt-error` so the CLI can explain a
   failure (for example a retired key or an expired envelope) rather than only
   reporting that something went wrong."
  (set! last-attempt-error #f)
  (catch #t
         thunk
         (lambda (key . args)
           (set! last-attempt-error (exception-message key args))
           #f)))

(define (failure-detail fallback)
  "Return a parenthesised explanation for the last failed `attempt`, or
   @var{fallback} when there is none."
  (if last-attempt-error
      (format #f "(~a)" last-attempt-error)
      fallback))

;; ====== token command ======

(define (owner-details options)
  "Build the owner-details alist from either --owner-details FILE or the
   individual --owner-* flags."
  (if (opt options "owner-details")
      (let ((datum (read-file-datum (opt options "owner-details"))))
        (unless (and (pair? datum) (list? datum))
          (cli-error "--owner-details must contain a Scheme alist"))
        datum)
      (let ((id (opt options "owner-id")))
        (unless id
          (cli-error
           "token generate: --owner-id (or --owner-details FILE) is required"))
        `((id . ,id)
          (email . ,(or (opt options "owner-email") ""))
          (name . ,(or (opt options "owner-name") ""))
          (permissions ,@(parse-permissions (opt options "permissions")))))))

(define (token-generate options)
  (let-values (((encryption-key signing-key keyring key-id) (require-keys options)))
    (let-values (((ttl-seconds expires-at) (expiry-args options)))
      (let* ((validity-string (or (opt options "validity-seconds")
                                  default-validity-seconds))
             (validity (string->number validity-string))
             (details (owner-details options))
             (token (and validity
                         (> validity 0)
                         (attempt
                          (lambda ()
                            (unsafe-generate-token #:encryption-key
                                                   encryption-key
                                                   #:signing-key signing-key
                                                   #:keyring keyring
                                                   #:key-id key-id
                                                   #:get-owner-details
                                                   (lambda () details)
                                                   #:token-validity-seconds
                                                   validity
                                                   #:ttl-seconds ttl-seconds
                                                   #:expires-at expires-at
                                                   #:kdf (kdf-option
                                                          options)))))))
        (unless (and validity (> validity 0))
          (cli-error "--validity-seconds must be a positive integer"))
        (if token
            (begin (display token) (newline))
            (cli-error "failed to generate token ~a"
                       (failure-detail "(check the keys and key id)")))))))

(define (token-input options)
  (or (opt options "token")
      (and (opt options "token-file")
           (string-trim-right (read-file (opt options "token-file"))))
      (cli-error "token decrypt: provide --token or --token-file")))

(define (token-decrypt options)
  (let-values (((encryption-key signing-key keyring key-id) (require-keys options)))
    (let-values (((enforce-expiry? max-age-seconds) (open-policy-args options)))
      (let ((payload (attempt
                      (lambda ()
                        (unsafe-decrypt-token #:token (token-input options)
                                              #:encryption-key encryption-key
                                              #:signing-key signing-key
                                              #:keyring keyring
                                              #:enforce-expiry? enforce-expiry?
                                              #:max-age-seconds
                                              max-age-seconds)))))
        (if payload
            (begin (write payload) (newline))
            (cli-error "failed to decrypt token ~a"
                       (failure-detail
                        "(wrong keys, tampered, expired, or corrupt token?)")))))))

(define (token-inspect options)
  (let* ((token (token-input options))
         (metadata (envelope-metadata #:sealed token)))
    (unless metadata
      (cli-error
       "token inspect: not a sealed envelope, so it carries no metadata"))
    (let ((number-or (lambda (value fallback)
                       (if value (number->string value) fallback))))
      (format #t "version:    ~a~%" (assoc-ref metadata 'version))
      (format #t "key-id:     ~a~%" (assoc-ref metadata 'key-id))
      (format #t "created-at: ~a~%"
              (number-or (assoc-ref metadata 'created-at) "n/a"))
      (format #t "expires-at: ~a~%"
              (number-or (assoc-ref metadata 'expires-at) "never"))
      (format #t "expired:    ~a~%"
              (if (envelope-expired? #:sealed token) "yes" "no")))))

(define (dispatch-token args)
  (when (null? args)
    (cli-error "token: missing subcommand (generate or decrypt)"))
  (let-values (((options positionals) (parse-options (cdr args))))
    (case (string->symbol (car args))
      ((generate) (token-generate options))
      ((decrypt) (token-decrypt options))
      ((inspect) (token-inspect options))
      (else (cli-error "token: unknown subcommand '~a'" (car args))))))

;; ====== object command ======

(define (input-string options)
  "The sealed/plaintext string, from --input FILE or standard input."
  (string-trim-right
   (if (opt options "input")
       (read-file (opt options "input"))
       (read-stdin-string))))

(define (object-encrypt options)
  (let-values (((encryption-key signing-key keyring key-id) (require-keys options)))
    (let-values (((ttl-seconds expires-at) (expiry-args options)))
      (let* ((datum (if (opt options "input")
                        (read-file-datum (opt options "input"))
                        (read (current-input-port))))
             (_ (when (eof-object? datum)
                  (cli-error "object encrypt: no Scheme datum to encrypt")))
             (sealed (attempt
                      (lambda ()
                        (unsafe-encrypt-object #:payload datum
                                               #:encryption-key
                                               encryption-key
                                               #:signing-key signing-key
                                               #:keyring keyring
                                               #:key-id key-id
                                               #:ttl-seconds ttl-seconds
                                               #:expires-at expires-at
                                               #:kdf (kdf-option
                                                      options))))))
        (if sealed
            (begin (display sealed) (newline))
            (cli-error "failed to encrypt object ~a"
                       (failure-detail "(check the keys and key id)")))))))

(define (object-decrypt options)
  (let-values (((encryption-key signing-key keyring key-id) (require-keys options)))
    (let-values (((enforce-expiry? max-age-seconds) (open-policy-args options)))
      (let ((datum (attempt
                    (lambda ()
                      (unsafe-decrypt-object #:object (input-string options)
                                             #:encryption-key encryption-key
                                             #:signing-key signing-key
                                             #:keyring keyring
                                             #:enforce-expiry?
                                             enforce-expiry?
                                             #:max-age-seconds
                                             max-age-seconds)))))
        (if datum
            (begin (write datum) (newline))
            (cli-error "failed to decrypt object ~a"
                       (failure-detail
                        "(wrong keys, tampered, expired, or corrupt input?)")))))))

(define (dispatch-object args)
  (when (null? args)
    (cli-error "object: missing subcommand (encrypt or decrypt)"))
  (let-values (((options positionals) (parse-options (cdr args))))
    (case (string->symbol (car args))
      ((encrypt) (object-encrypt options))
      ((decrypt) (object-decrypt options))
      (else (cli-error "object: unknown subcommand '~a'" (car args))))))

;; ====== password command ======

(define (password-strength-command options positionals)
  (let ((password (if (pair? positionals)
                      (car positionals)
                      (let ((line (read-line (current-input-port))))
                        (if (eof-object? line)
                            (cli-error "password strength: no password provided")
                            line)))))
    (let ((report (password-strength #:password password)))
      (format #t "score:   ~a (~a)~%"
              (assoc-ref report 'score) (assoc-ref report 'label))
      (format #t "entropy: ~a bits~%" (assoc-ref report 'entropy))
      (format #t "length:  ~a~%" (assoc-ref report 'length))
      (format #t "classes: ~a~%" (assoc-ref report 'classes))
      (let ((feedback (assoc-ref report 'feedback)))
        (when (pair? feedback)
          (format #t "suggestions:~%")
          (for-each (lambda (suggestion)
                      (format #t "  - ~a~%" suggestion))
                    feedback))))))

(define (password-generate-command options)
  (let* ((length-string (or (opt options "length") "24"))
         (length (string->number length-string))
         (include-symbols (not (opt options "no-symbols"))))
    (unless (and length (integer? length) (> length 0))
      (cli-error "--length must be a positive integer"))
    (display (generate-strong-password #:length length
                                       #:include-symbols include-symbols))
    (newline)))

(define (dispatch-password args)
  (when (null? args)
    (cli-error "password: missing subcommand (strength or generate)"))
  (let-values (((options positionals) (parse-options (cdr args))))
    (case (string->symbol (car args))
      ((strength) (password-strength-command options positionals))
      ((generate) (password-generate-command options))
      (else (cli-error "password: unknown subcommand '~a'" (car args))))))

;; ====== entry point ======

(define (dispatch args)
  (cond ((null? args)
         (display usage)
         (cli-error "no command given; see 'bewaking help'"))
        ((member (car args) '("help" "-h" "--help"))
         (display usage))
        ((member (car args) '("--version" "-v"))
         (format #t "~a command-line interface~%" program-name))
        ((equal? (car args) "token") (dispatch-token (cdr args)))
        ((equal? (car args) "object") (dispatch-object (cdr args)))
        ((equal? (car args) "password") (dispatch-password (cdr args)))
        (else (cli-error "unknown command '~a'; see 'bewaking help'"
                         (car args)))))

(define (run args)
  "Run the bewaking command-line interface with @var{args} (a list of strings,
   without the program name). Returns the process exit code: 0 on success and
   1 on any error or usage problem."
  (catch 'cli-error
    (lambda ()
      (dispatch args)
      0)
    (lambda (key message)
      (format (current-error-port) "~a: ~a~%" program-name message)
      1)))
