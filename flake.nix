# bewaking
#
# SPDX-License-Identifier: MIT
# Copyright © Josep Bigorra <jjbigorra@gmail.com>

{
  description = "Bewaking - authentication and authorization library for GNU Guile";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # guile-uuid has no package in nixpkgs yet, so the branch of this fork that
    # adds one is an input and the overlay below reads the package from it.
    # Drop the input and the overlay together, once that branch is merged and
    # nixos-unstable carries guile-uuid.
    guile-uuid-src = {
      url = "github:jjba23/nixpkgs/guile-uuid-init";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, guile-uuid-src }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      pkgsFor = system: import nixpkgs {
        inherit system;
        overlays = [
          (final: prev: {
            guile-uuid = final.callPackage
              "${guile-uuid-src}/pkgs/by-name/gu/guile-uuid/package.nix" { };
          })
        ];
      };
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = pkgsFor system;
        in
        {
          guile-bewaking = pkgs.callPackage ./default.nix { };
          default = self.packages.${system}.guile-bewaking;
        });

      devShells = forAllSystems (system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            inputsFrom = [ self.packages.${system}.guile-bewaking ];
            packages = with pkgs; [
              guile
              guile-uuid
              guile-gcrypt
            ];
            shellHook = ''
              export GUILE_LOAD_PATH="$PWD/src''${GUILE_LOAD_PATH:+:$GUILE_LOAD_PATH}"
            '';
          };
        });
    };
}
