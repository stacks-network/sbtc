{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
  };
  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          overlays = [ (import rust-overlay) ];
          pkgs = import nixpkgs {
            inherit system overlays;
          };
          toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        in
        with pkgs;
        {
          devShells.default = mkShell {
            RUSTFMT = "${toolchain}/bin/rustfmt";
            GREETING = "Welcome, sBTC developer!";
            shellHook = ''
              echo $GREETING
            '';

            buildInputs = [
              toolchain

              cargo-lambda
              gnumake
              jdk21_headless
              nodejs
              pnpm
              protobuf
            ] ++ lib.optionals pkgs.stdenv.isDarwin [
              pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
            ];
          };
        }
      );
}

