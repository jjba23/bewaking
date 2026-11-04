# bewaking

# Copyright © Josep Bigorra <jjbigorra@gmail.com>

# bewaking is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# bewaking is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with bewaking.  If not, see <https://www.gnu.org/licenses/>.

# The package of this checkout as it stands.  It is the same derivation as the
# `guile-bewaking' package in nixpkgs -- same phases, same layout under $out --
# so that a change which breaks this build breaks that one for the same reason.
# What differs is the source: this file builds the working tree, while nixpkgs
# pins a released tag and its hash.  Keep `version' in step with the tag you
# release, because nothing here can read it from the library.

{ lib
, stdenv
, guile
, guile-uuid
, guile-gcrypt
}:

stdenv.mkDerivation {
  pname = "guile-bewaking";
  version = "0.4.7";

  src = ./.;

  nativeBuildInputs = [ guile ];

  buildInputs = [ guile ];

  propagatedBuildInputs = [
    guile-uuid
    guile-gcrypt
  ];

  buildPhase = ''
    runHook preBuild

    siteDir=$out/${guile.siteDir}
    install -d "$siteDir"
    cp -R src/. "$siteDir"/

    export GUILE_AUTO_COMPILE=0
    export GUILE_LOAD_PATH="$siteDir''${GUILE_LOAD_PATH:+:$GUILE_LOAD_PATH}"

    find src -name '*.scm' | while IFS= read -r file; do
      rel="''${file#src/}"
      guild compile -o "$siteDir/''${rel%.scm}.go" "$file"
    done

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    runHook postInstall
  '';

  meta = with lib; {
    description = "Authentication and authorization library for GNU Guile";
    homepage = "https://codeberg.org/jjba23/bewaking";
    license = licenses.lgpl3Plus;
    platforms = guile.meta.platforms;
  };
}
