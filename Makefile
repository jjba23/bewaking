# bewaking

# Copyright © Josep Bigorra <jjbigorra@gmail.com>

# bewaking is free software: you can redistribute it and/or modify
# it under the terms of the Lesser GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# bewaking is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# Lesser GNU General Public License for more details.

# You should have received a copy of the Lesser GNU General Public License
# along with bewaking.  If not, see <https://www.gnu.org/licenses/>.

.PHONY: test docs

API_DOCS_CSS_URL:="https://jointhefreeworld.org/static-assets/api-docs/css/style.css"
DEPLOY_WWW="/srv/http/jointhefreeworld.org"


# Logging helpers

define bewaking-log-info
	@printf "\n\033[1m[INFO] $(shell date --rfc-3339=seconds) - %s\033[0m\n" $(1)
endef

# Target to format source code files according to the style guide
# Find all .scm files and format them using 'guix style'
fmt:
	$(call bewaking-log-info,"formatting all Scheme files")
	find . -maxdepth 8 -name "*.scm" -type f -exec guix style -f {} \;


# Development REPL
repl:
	guix shell -m manifest.scm -- \
		guile \
		-L ./src \
		-c '((@ (ares server) run-nrepl-server))'

# Unit tests
test:
	guix shell -m manifest.scm -- \
		guile -L ./src \
		-L ./test \
		-c "((@ (bewaking test-runners) run-project-tests))"

# docs: Generate technical API documentation
docs:
	rm -rfv doc
	guix shell -m manifest.scm -- documenta api ./src/bewaking
	guix shell -m manifest.scm -- texi2any -v --html \
		--css-ref=$(API_DOCS_CSS_URL) ./doc/api/index.texi
	mv ./index ./doc/api-dist

# deploy: Deploys the documentation to a web server directory.
deploy: docs
	rm -rfv $(DEPLOY_WWW)/api-docs/bewaking
	mkdir -p $(DEPLOY_WWW)/api-docs/bewaking
	mv doc/api-dist/* $(DEPLOY_WWW)/api-docs/bewaking/
	rm -rfv doc
