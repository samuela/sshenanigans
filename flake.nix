{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nix-community/naersk";
    # Build with the same nixpkgs (and thus the same Rust toolchain) as the
    # dev shell, instead of naersk pulling in a second, separately pinned one.
    naersk.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, utils, naersk }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages."${system}";
        naersk-lib = naersk.lib."${system}";
      in rec {
        # `nix build`
        packages.default = naersk-lib.buildPackage {
          pname = "sshenanigans";
          root = ./.;
        };

        # `nix run`
        apps.default = utils.lib.mkApp { drv = packages.default; };

        # `nix develop`
        devShell = with pkgs;
          mkShell {
            nativeBuildInputs = ([ cargo rustc rustfmt ]
              ++ lib.optionals stdenv.isDarwin [ libiconv ]);
          };
      });
}
