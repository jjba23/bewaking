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

.PHONY: test

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
