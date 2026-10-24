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

;; Commentary:
;;
;; Repository tasks, run with maak.
;;
;; The tasks name programs rather than shell lines: `run' builds the argv, so
;; a path with a space in it stays one argument and a program that fails raises
;; where the task can see it.  Commands that need the project's own libraries
;; go through `time-machine-manifest-shell', which enters the manifest at the
;; revision channels.scm pins; the documentation steps are separate calls so
;; each one fails on its own rather than behind an `&&'.
;;
;; Images are built and run through `container-build' and `container-run', which
;; pick podman or docker from what the machine has instead of naming one.

(define-module (maak)
  #:declarative? #t
  #:use-module (maak maak)
  ;; The container helpers are imported under a prefix because the task names
  ;; below are the ones maak exposes on the command line -- `maak
  ;; container-build' -- and a task may not shadow the helper it calls.
  #:use-module ((maak container) #:prefix ct:))

;; ====== Project constants ======

;; The URL for the CSS style-sheet used to style API documentation.
(define api-docs-css-url
  "https://jointhefreeworld.org/static/css/jointhefreeworld.css")

;; The absolute path to the directory where the API documentation is deployed.
(define deploy-api-docs-dir
  "/srv/http/jointhefreeworld.org")

;; The name of the project, represented as a symbol.
(define project-name
  'bewaking)

;; The image container-build tags.
(define container-image
  "bewaking")

;; The source files watched by `hot-reload'.
(define hot-reload-file-types
  '(scm))

;; ====== Maak tasks ======

(define (compile)
  "Compile all project source code."
  (time-machine-manifest-shell (list "guild" "compile" "-L" "./src" "-W3"
                                     "./src/**/*.scm")
                               #:verbose? #t))

(define (fmt)
  "Format Scheme source code files according to the Guix style guide."
  (run (list "find" "." "-maxdepth" "8" "-name" "*.scm" "-type" "f"
             "-exec" "guix" "style" "-f" "{}" ";")
       #:verbose? #t))

(define (repl)
  "Development REPL."
  (time-machine-manifest-shell (list "guile" "-L" "./src"
                                     "-c" "'((@ (ares server) run-nrepl-server))'")
                               #:verbose? #t))

(define (docs)
  "Generate technical API documentation for Bewaking.

The two generators are separate calls -- `documenta' writes the Texinfo tree,
`texi2any' renders it -- so a failure names the step that failed instead of
being swallowed by the chain."
  (delete-file-recursively "doc")
  (time-machine-manifest-shell (list "documenta" "api"
                                     (~ "./src/~a" project-name))
                               #:verbose? #t)
  (time-machine-manifest-shell (list "texi2any" "-v" "--html"
                                     (~ "--css-ref=~a" api-docs-css-url)
                                     "./doc/api/index.texi")
                               #:verbose? #t)
  (mv "./index" "./doc/api-dist"))

(define (deploy)
  "Generate documentation for the project and publish to the web directory."
  (docs)
  (remkdir-p (~ "~a/api-docs/~a" deploy-api-docs-dir project-name))
  (mv "doc/api-dist/*"
      (~ "~a/api-docs/~a" deploy-api-docs-dir project-name)
      #:expand? #t)
  (delete-file-recursively "doc"))

(define (test)
  "Run the project's tests."
  (time-machine-manifest-shell (list "guile" "-L" "./src" "-L" "./test"
                                     "-c" "'((@ (veritas runner) run-tests))'")
                               #:verbose? #t))

(define (hot-reload)
  "Watch the sources and rerun the tests on every change."
  (time-machine-manifest-shell
   (list "watchexec" "'maak test'"
         "--clear"
         "--exts" (string-join (map symbol->string hot-reload-file-types)
                               ",")
         "--on-busy-update=restart"
         "--shell" "bash"
         "--watch" ".")
   #:verbose? #t))

(define (hr)
  "Alias for hot-reload."
  (hot-reload))

(define (dev)
  "Developer's setup: the hot-reload loop."
  (hot-reload))

(define (default)
  "List the tasks this project defines."
  (list-tasks))

;; ====== Container tasks ======

(define (container-build)
  "Build the container image for bewaking from the repository root."
  (ct:container-build "."
                      #:tag (~ "~a:latest" container-image)
                      #:verbose? #t))

(define (container-run)
  "Run the container image for bewaking in the foreground."
  (ct:container-run container-image
                    #:interactive? #t
                    #:tty? #t
                    #:verbose? #t))

(define (package-docker)
  "Build the container image for bewaking."
  (container-build))
