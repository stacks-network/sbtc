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

          smithy-cli = pkgs.stdenv.mkDerivation rec {
            smithy-system-hash = {
              "aarch64-darwin" = [ "darwin-aarch64" "sha256-s/y8turEQfvGwJ2xz70SwAIlg1fk4miOPZ5SapO6tJU=" ];
              "x86_64-darwin" = [ "darwin-x86_64" "sha256-iTJ4PbFfxG+sU2B4Viu5fG0K44zqcU/I3Y7sTlFPAuQ=" ];
              "aarch64-linux" = [ "linux-aarch64" "sha256-3SSmT1t5ctgVa3lXnjGRDb2OJ3j272RTUm1aQ1Itjlo=" ];
              "x86_64-linux" = [ "linux-x86_64" "sha256-TleL3pvFg/LemPFktzUDVI1YYzh78yKtHwuc0l33x1I=" ];
            }.${system};

            pname = "smithy-cli";
            version = "1.51.0";
            base_url = "https://github.com/smithy-lang/smithy/releases/download/";
            src = pkgs.fetchzip {
              url = "${base_url}/${version}/smithy-cli-${builtins.elemAt smithy-system-hash 0}.zip";
              hash = builtins.elemAt smithy-system-hash 1;
            };
            buildPhase = ''
              mkdir $out
              mv * $out
            '';
          };
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
              smithy-cli

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

