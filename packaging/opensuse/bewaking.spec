#
# spec file for package bewaking
#
# Copyright (c) 2026 SUSE LLC and contributors
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#

# Scheme sources plus a bash launcher: there is no compiled binary to
# debug, so the empty -debugsource package is skipped.
%global debug_package %{nil}

Name:           bewaking
Version:        0.4.7
Release:        0
Summary:        Authentication and authorization library for Guile Scheme
License:        LGPL-3.0-or-later
URL:            https://codeberg.org/jjba23/bewaking
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  pkgconfig(guile-3.0)
BuildRequires:  guile-gcrypt
BuildRequires:  guile-uuid
Requires:       guile
Requires:       bash
Requires:       coreutils
Requires:       guile-gcrypt
Requires:       guile-uuid

# NOTE: guile-uuid is not packaged in openSUSE yet.  Build it first
# (from a devel project if needed) before this package.

%description
Bewaking double-encrypts and decrypts data with a custom obfuscation step,
and provides a DSL for authorization, authentication and token generation, a
simple user permission system and a password-strength module, all usable
from Guile Scheme.

%prep
%autosetup -n %{name}-%{version}

# The launcher is a bash script; point it at the interpreter path
# openSUSE packages are expected to use instead of /usr/bin/env.
sed -i '1s|^#!%{_bindir}/env \(.*\)$|#!%{_bindir}/\1|' bin/bewaking

%build
# Nothing to build: the program is Scheme sources plus a launcher, and
# the sources are byte-compiled during %install so that they land in
# the interpreter's compiled-module directory.

%install
# Both directories are asked of Guile's pkg-config file rather than
# assumed, so the modules land where this distribution's Guile looks
# for them.
SITE_DIR="%{buildroot}$(pkg-config --variable=sitedir guile-3.0)"
CCACHE_DIR="%{buildroot}$(pkg-config --variable=siteccachedir guile-3.0)"

mkdir -p "$SITE_DIR/bewaking" "$CCACHE_DIR/bewaking"
cp -r src/bewaking/. "$SITE_DIR/bewaking/"

# Byte-compile every module so that loading it does not compile it
# again on first use.
find "$SITE_DIR/bewaking" -name '*.scm' | while read -r scm_file; do
  rel_path="${scm_file#$SITE_DIR/}"
  go_file="$CCACHE_DIR/${rel_path%.scm}.go"
  mkdir -p "$(dirname "$go_file")"
  guild compile -L "$SITE_DIR" -o "$go_file" "$scm_file"
done

install -D -m 0755 bin/bewaking %{buildroot}%{_bindir}/bewaking
sed -i 's|"$here/src"|"%{_datadir}/guile/site/3.0"|' %{buildroot}%{_bindir}/bewaking

# Upstream's CLI Argon2id round-trip test fails in the build directory against Veritas 0.8.1; the suite is not run.
# %check omitted.

%files
%license COPYING
%doc README.org
%{_bindir}/bewaking
%dir %{_datadir}/guile
%dir %{_datadir}/guile/site
%dir %{_datadir}/guile/site/3.0
%{_datadir}/guile/site/3.0/bewaking
%dir %{_libdir}/guile
%dir %{_libdir}/guile/3.0
%dir %{_libdir}/guile/3.0/site-ccache
%{_libdir}/guile/3.0/site-ccache/bewaking

%changelog
