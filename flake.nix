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
      rec {
        # `nix build`
        packages.default = naersk-lib.buildPackage {
          pname = "sshenanigans";
          root = ./.;
        };

        # `nix run`
        apps.default = utils.lib.mkApp {
          drv = packages.default;
        };

        # `nix develop`
        devShell = pkgs.mkShell {
          nativeBuildInputs = with pkgs; ([ rustc cargo rustfmt ] ++ lib.optionals stdenv.isDarwin [ libiconv ]);
        };
      });
}
