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
    crane = {
      url = "github:ipetkov/crane";
    };
  };
  outputs =
    {
      crane,
      nixpkgs,
      flake-utils,
      rust-overlay,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        RUSTFMT = "${toolchain}/bin/rustfmt";
        craneLib = crane.mkLib pkgs;

        workspaceName = "sbtc";
        root = ./.;

        inherit (pkgs) lib;

        filesetPerPackage = {
          workspace = [
            (craneLib.fileset.commonCargoSources ./.)
          ];
          signer = [
            (craneLib.fileset.commonCargoSources ./signer)
            (lib.fileset.fileFilter (file: file.hasExt "clar") root)
            ./signer/migrations
            ./signer/README.md
            ./signer/src/config/default.toml
          ];
          blocklist-client = [
            ./blocklist-client/README.md
            ./blocklist-client/src/config/default.toml
          ];
          emily = [
            ./emily/handler/README.md
          ];
        };

        testFilesetPerPackage = {
          signer = [
            ./signer/tests/fixtures
          ];
          emily = [
            ./emily/handler/tests/fixtures
            ./emily/openapi-gen/generated-specs
          ];
        };

        # If not better specified, we default to the overall sources.
        src = pkgs.lib.fileset.toSource {
          inherit root;
          fileset = lib.fileset.unions (
            [ (craneLib.fileset.commonCargoSources root) ]
            ++ (lib.lists.flatten (lib.attrsets.attrValues filesetPerPackage))
            ++ (lib.lists.flatten (lib.attrsets.attrValues testFilesetPerPackage))
          );
        };

        # Common derivation arguments used for all builds
        commonArgs = {
          inherit src RUSTFMT;
          strictDeps = true;

          buildInputs =
            with pkgs;
            (
              [
                # Add additional build inputs here
              ]
              ++ lib.optionals stdenv.isDarwin [
                # Darwin specific inputs
                darwin.apple_sdk.frameworks.SystemConfiguration
              ]
            );

          nativeBuildInputs = [ ];
        };

        # Build *just* the cargo dependencies, so we can reuse
        # all of that work (e.g. via cachix) when running in CI
        cargoArtifacts = craneLib.buildDepsOnly (
          commonArgs
          // {
            # Additional arguments specific to this derivation can be added here.
            # Be warned that using `//` will not do a deep copy of nested
            # structures

            # NOTE: This overrides `src` defined above:
            # To build dependencies we don't care if `clar` files have changed.
            src = craneLib.cleanCargoSource ./.;
            pname = "${workspaceName}";
            version = "0.0.0"; # FIXME
          }
        );

        workspaceClippy = craneLib.cargoClippy (
          commonArgs
          // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          }
        );

        workspaceFmt = craneLib.cargoFmt {
          inherit src;
        };

        derivationForPackage =
          package:
          let
            src = pkgs.lib.fileset.toSource {
              inherit root;
              fileset = (lib.fileset.unions (filesetPerPackage.${package} ++ filesetPerPackage.workspace));
            };

            inherit (craneLib.crateNameFromCargoToml { cargoToml = ./${package}/Cargo.toml; }) pname version;
          in
          craneLib.buildPackage (
            commonArgs
            // rec {
              inherit
                src
                cargoArtifacts
                pname
                version
                ;

              cargoExtraArgs = "-p ${pname}";

              # NOTE: Checks are currently disabled because they require on a
              # hardcoded path for the standard signer config. Plus, we want to use `nextest` anyway.
              doCheck = false;
            }
          );

        signer = derivationForPackage "signer";
        blocklistClient = derivationForPackage "blocklist-client";

        # TODO: Untested, will require Linux host.
        signerDocker = pkgs.dockerTools.streamLayeredImage {
          name = "signer";
          tag = "latest"; # FIXME

          contents = with pkgs; [
            signer
            cacert # SSL certificates
            gettext # provides `envsubst`
            gh # for attestation verification
          ];

          config.Cmd = [
            "/bin/signer"
            "--config"
            "/signer-config.toml"
            "--migrate-db"
          ];
        };

        devShellConfig = {
          inherit RUSTFMT;
          GREETING = "Welcome, sBTC developer!";

          shellHook = ''
            echo $GREETING
          '';

          buildInputs =
            commonArgs.buildInputs
            ++ (with pkgs; [
              toolchain

              cargo-lambda
              cargo-nextest
              gnumake
              jdk21_headless
              nodejs
              pnpm
              protobuf
            ]);
        };

        devShell = pkgs.mkShell devShellConfig;
        devShellWithMold = pkgs.mkShell.override {
          stdenv = pkgs.stdenvAdapters.useMoldLinker pkgs.clangStdenv;
        } devShellConfig;
      in
      {
        packages = {
          inherit signer signerDocker blocklistClient;
          default = signer;
        };
        checks = {
          inherit workspaceClippy workspaceFmt;
        };

        devShells = {
          inherit devShell devShellWithMold;
          default = devShell;
        };
      }
    );
}
