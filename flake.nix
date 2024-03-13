{
  inputs = {
    utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nix-community/naersk";
  };

  outputs = { self, nixpkgs, utils, naersk }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages."${system}";
        naersk-lib = naersk.lib."${system}";
      in
      with pkgs;
      rec {
        # `nix build`
        packages.default = naersk-lib.buildPackage {
          pname = "sshenanigans";
          root = ./.;

          # See https://github.com/nix-community/naersk?tab=readme-ov-file#using-openssl.
          nativeBuildInputs = [ pkg-config ];
          buildInputs = [ openssl.dev ];
        };

        # `nix run`
        apps.default = utils.lib.mkApp {
          drv = packages.default;
        };

        # `nix develop`
        devShell = mkShell {
          nativeBuildInputs = ([
            rustc
            cargo
            rustfmt

            # See https://nixos.wiki/wiki/Rust#Building_Rust_crates_that_require_external_system_libraries.
            # sshenanigans uses russh with the "openssl" feature, which requires this.
            openssl.dev
            pkg-config
          ] ++ lib.optionals stdenv.isDarwin [ libiconv ]);
        };
      });
}
