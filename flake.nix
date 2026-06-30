{
  description = "Nucleus - Extremely lightweight Docker alternative for agents";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    crane.url = "github:ipetkov/crane";

    flake-utils.url = "github:numtide/flake-utils";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, crane, flake-utils, rust-overlay, advisory-db, ... }:
    {
      # NixOS module for declarative Nucleus service management
      nixosModules.default = import ./nix/module.nix;
      nixosModules.nucleus = self.nixosModules.default;

      # Helper: build a minimal rootfs for a Nucleus production container.
      # Usage in a flake:
      #   nucleus.lib.mkRootfs { pkgs = import nixpkgs { system = "x86_64-linux"; };
      #     packages = [ pkgs.coreutils pkgs.curl pkgs.cacert ]; }
      lib.mkRootfs = { pkgs, packages ? [ ], name ? "nucleus-rootfs" }:
        let
          baseRootfs = pkgs.buildEnv {
            inherit name;
            paths = [ pkgs.coreutils pkgs.bashInteractive ] ++ packages;
            pathsToLink = [ "/bin" "/sbin" "/lib" "/lib64" "/usr" "/etc" ];
          };
          closure = pkgs.closureInfo {
            rootPaths = [ baseRootfs ];
          };
        in
        pkgs.runCommand name {
          nativeBuildInputs = [ pkgs.coreutils pkgs.findutils ];
        } ''
          mkdir -p "$out"
          for path in bin sbin lib lib64 usr etc; do
            if [ -e "${baseRootfs}/$path" ]; then
              mkdir -p "$out/$path"
              cp -a -P --no-preserve=mode,ownership "${baseRootfs}/$path/." "$out/$path/"
            fi
          done
          mkdir -p "$out/etc"
          rm -f "$out/etc/resolv.conf"
          : > "$out/etc/resolv.conf"

          if [ -x "$out/bin/bash" ] && [ ! -e "$out/bin/sh" ]; then
            ln -s bash "$out/bin/sh"
          fi
          if [ -x "$out/bin/env" ]; then
            mkdir -p "$out/usr/bin"
            if [ ! -e "$out/usr/bin/env" ]; then
              ln -s ../../bin/env "$out/usr/bin/env"
            fi
          fi

          mkdir -p "$out/nix/store"
          store_paths="$out/.nucleus-rootfs-store-paths"
          : > "$store_paths"
          while IFS= read -r store_path; do
            case "$store_path" in
              /nix/store/*)
                basename="$(basename "$store_path")"
                mkdir -p "$out/nix/store/$basename"
                printf '%s\n' "$store_path" >> "$store_paths"
                ;;
            esac
          done < "${closure}/store-paths"
          sort -u -o "$store_paths" "$store_paths"

          manifest="$out/.nucleus-rootfs-sha256"
          find -L "$out" -type f ! -name ".nucleus-rootfs-sha256" -printf '%P\0' \
            | sort -z \
            | while IFS= read -r -d "" rel; do
                digest="$(sha256sum "$out/$rel" | cut -d' ' -f1)"
                printf '%s\t%s\n' "$digest" "$rel"
              done > "$manifest"
        '';

      # Helper: build a cold, thin Nucleus image directly from a Nix rootfs.
      # Build-time images omit image.sig because the Nix store/substituter
      # signature is the integrity root and do not contain runtime overlay diffs.
      lib.mkImage =
        { pkgs
        , rootfs
        , config
        , name ? "nucleus-image"
        }:
        assert pkgs.lib.assertMsg (config ? command) "nucleus.lib.mkImage requires config.command";
        let
          cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
          imageConfig = {
            command = config.command;
            env = config.env or { };
            workdir = config.workdir or "/workspace";
            uid = config.uid or 0;
            gid = config.gid or 0;
            additional_gids = config.additionalGids or (config.additional_gids or [ ]);
          };
        in
        pkgs.runCommand name {
          nativeBuildInputs = [ pkgs.coreutils pkgs.python3 ];
          passAsFile = [ "imageConfigJson" ];
          imageConfigJson = builtins.toJSON imageConfig;
          nucleusVersion = cargoToml.package.version;
        } ''
          mkdir -p "$out"
          cp "${rootfs}/.nucleus-rootfs-sha256" "$out/rootfs.sha256"
          cp "${rootfs}/.nucleus-rootfs-store-paths" "$out/store-paths"

          ROOTFS_PATH="${rootfs}" \
          IMAGE_CONFIG_JSON_PATH="$imageConfigJsonPath" \
          NUCLEUS_VERSION="$nucleusVersion" \
          python3 - <<'PY'
          import hashlib
          import json
          import os
          from pathlib import Path

          rootfs = os.environ["ROOTFS_PATH"]
          out = Path(os.environ["out"])
          image_config_path = Path(os.environ["IMAGE_CONFIG_JSON_PATH"])
          image_config_raw = json.loads(image_config_path.read_text())
          image_config = {
              "command": list(image_config_raw["command"]),
              "env": dict(sorted(image_config_raw.get("env", {}).items())),
              "workdir": image_config_raw.get("workdir", "/workspace"),
              "uid": int(image_config_raw.get("uid", 0)),
              "gid": int(image_config_raw.get("gid", 0)),
              "additional_gids": list(image_config_raw.get("additional_gids", [])),
          }

          store_paths = sorted({
              line.strip()
              for line in (out / "store-paths").read_text().splitlines()
              if line.strip()
          })
          attestation = {}
          for line in (out / "rootfs.sha256").read_text().splitlines():
              if not line.strip():
                  continue
              digest, rel = line.split("\t", 1)
              attestation[rel] = digest
          attestation = dict(sorted(attestation.items()))

          manifest = {
              "schema_version": 2,
              "image_id": "",
              "created_at": 0,
              "nucleus_version": os.environ["NUCLEUS_VERSION"],
              "base": {
                  "rootfs_path": rootfs,
                  "store_paths": store_paths,
                  "attestation": attestation,
              },
              "diff": None,
              "config": image_config,
          }
          canonical = json.dumps(manifest, separators=(",", ":")).encode()
          manifest["image_id"] = hashlib.sha256(canonical).hexdigest()
          (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
          PY
        '';

      # Helper: build a reusable rootfs for ephemeral provider agents.
      # This is intentionally broader than mkRootfs's minimal default: Mitos
      # and similar launchers need shells, git, TLS, provider CLIs, compilers,
      # language runtimes, and package managers available inside the sandbox.
      lib.mkAgentToolchainRootfs =
        { pkgs
        , providerPackages ? [ ]
        , extraPackages ? [ ]
        , name ? "nucleus-agent-toolchain-rootfs"
        }:
        self.lib.mkRootfs {
          inherit pkgs name;
          packages = (with pkgs; [
            bashInteractive
            coreutils
            findutils
            gnugrep
            gnused
            gawk
            diffutils
            patch
            gnutar
            gzip
            bzip2
            xz
            zstd
            zip
            unzip
            which
            file
            git
            openssh
            curl
            cacert
            jq
            ripgrep
            nodejs
            python3
            rustc
            cargo
            go
            gcc
            gnumake
            pkg-config
          ]) ++ providerPackages ++ extraPackages;
        };
    } //
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        inherit (pkgs) lib;

        gvisor = pkgs.gvisor.overrideAttrs (old: {
          patches = (old.patches or [ ]) ++ [
            ./nix/patches/gvisor-runsc-real-exe-path.patch
          ];
        });
        gvisorRuntimePkgs = lib.optionals pkgs.stdenv.isLinux [ gvisor ];
        networkRuntimePkgs = lib.optionals pkgs.stdenv.isLinux [ pkgs.iptables pkgs.slirp4netns ];
        runtimePath = lib.makeBinPath (gvisorRuntimePkgs ++ networkRuntimePkgs);

        rustToolchain = pkgs.rust-bin.stable.latest.default;
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Check if Cargo.lock exists
        cargoLockExists = builtins.pathExists ./Cargo.lock;

        srcRoot = ./.;
        src =
          if cargoLockExists then
            lib.cleanSourceWith {
              src = srcRoot;
              filter =
                path: type:
                let
                  pathString = toString path;
                  rootString = toString srcRoot;
                  relativePath = lib.removePrefix "${rootString}/" pathString;
                in
                craneLib.filterCargoSources path type
                || relativePath == "formal"
                || lib.hasPrefix "formal/" relativePath
                || relativePath == "intent"
                || lib.hasPrefix "intent/" relativePath
                || relativePath == "nix/patches/gvisor-runsc-real-exe-path.patch";
            }
          else
            srcRoot;

        # Common arguments
        commonArgs = {
          inherit src;
          pname = "nucleus";
          version = "0.3.9";
          strictDeps = true;

          nativeBuildInputs = [
            pkgs.pkg-config
          ];

          buildInputs = [
            pkgs.openssl
          ] ++ lib.optionals pkgs.stdenv.isDarwin [
            pkgs.libiconv
          ];
        };

        # Build dependencies only (for caching)
        cargoArtifacts = if cargoLockExists then craneLib.buildDepsOnly commonArgs else null;

        # Build the actual crate
        my-crate = if cargoLockExists then craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          nativeCheckInputs = gvisorRuntimePkgs;
          nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ pkgs.makeWrapper ];
          postFixup = lib.optionalString pkgs.stdenv.isLinux ''
            wrapProgram $out/bin/nucleus --prefix PATH : "${runtimePath}"
          '';
        }) else null;

        # Apalache - TLA+ model checker
        apalacheVersion = "0.52.2";
        apalache = pkgs.stdenv.mkDerivation {
          pname = "apalache";
          version = apalacheVersion;

          src = pkgs.fetchurl {
            url = "https://github.com/apalache-mc/apalache/releases/download/v${apalacheVersion}/apalache-${apalacheVersion}.tgz";
            sha256 = "e0ebea7e45c8f99df8d92f2755101dda84ab71df06d1ec3a21955d3b53a886e2";
          };

          nativeBuildInputs = [ pkgs.makeWrapper ];
          buildInputs = [ pkgs.jdk17_headless ];

          dontConfigure = true;
          dontBuild = true;

          unpackPhase = ''
            mkdir -p src
            tar xzf $src -C src --strip-components=1
          '';

          installPhase = ''
            mkdir -p $out/share/apalache $out/bin
            cp -r src/lib $out/share/apalache/
            cp -r src/bin $out/share/apalache/

            makeWrapper $out/share/apalache/bin/apalache-mc $out/bin/apalache-mc \
              --set JAVA_HOME "${pkgs.jdk17_headless}" \
              --prefix PATH : "${pkgs.jdk17_headless}/bin"
          '';
        };

      in
      {
        checks = lib.optionalAttrs cargoLockExists {
          inherit my-crate;

          my-crate-clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });

          my-crate-doc = craneLib.cargoDoc (commonArgs // {
            inherit cargoArtifacts;
          });

          my-crate-fmt = craneLib.cargoFmt {
            inherit src;
            pname = "nucleus";
            version = "0.3.9";
          };

          my-crate-audit = craneLib.cargoAudit {
            inherit src advisory-db;
            pname = "nucleus";
            version = "0.3.9";
          };

          my-crate-deny = craneLib.cargoDeny {
            inherit src;
            pname = "nucleus";
            version = "0.3.9";
          };

          my-crate-nextest = craneLib.cargoNextest (commonArgs // {
            inherit cargoArtifacts;
            nativeCheckInputs = gvisorRuntimePkgs;
            partitions = 1;
            partitionType = "count";
          });
        };

        packages = lib.optionalAttrs cargoLockExists {
          default = my-crate;
          agent-toolchain-rootfs = self.lib.mkAgentToolchainRootfs {
            inherit pkgs;
          };
        };

        apps = lib.optionalAttrs cargoLockExists {
          default = flake-utils.lib.mkApp {
            drv = my-crate;
          };
        };

        devShells.default = craneLib.devShell {
          checks = self.checks.${system};

          OPENSSL_DIR = "${pkgs.openssl.dev}";
          OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";

          shellHook = ''
            if [ "''${NUCLEUS_ENABLE_SCCACHE:-0}" = "1" ]; then
              export RUSTC_WRAPPER="${pkgs.sccache}/bin/sccache"
              export SCCACHE_CACHE_SIZE="5G"
            else
              unset RUSTC_WRAPPER
            fi
          '';

          packages = with pkgs; [
            # Build tools
            pkg-config
            openssl
            openssl.dev

            # Rust tooling
            rust-analyzer
            cargo-watch
            cargo-nextest
            sccache
            just

            # Container runtime
            gvisor
            iptables
            slirp4netns

            # Formal verification tools
            z3
            apalache
          ];
        };
      });
}
