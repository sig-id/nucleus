{
  description = "PostgreSQL 18 benchmark: default I/O vs io_uring, baremetal vs Nucleus (native) vs Nucleus (gVisor)";

  inputs = {
    # Use the same nixpkgs revision as the main nucleus flake so gvisor
    # builds match and we avoid version skew (e.g. Go build failures).
    nixpkgs.follows = "nucleus/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    nucleus.url = "path:../..";
  };

  outputs = { self, nixpkgs, flake-utils, nucleus, ... }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        pkgs = import nixpkgs { inherit system; };

        # PostgreSQL 18 – nixpkgs already builds with --with-liburing,
        # so both io_method=worker and io_method=io_uring use the same binary.
        pg18 = pkgs.postgresql_18;

        nucleusPkg = nucleus.packages.${system}.default;

        benchScript = pkgs.writeShellApplication {
          name = "pg18-bench";
          runtimeInputs = [
            pg18
            nucleusPkg
            pkgs.gvisor
            pkgs.coreutils
            pkgs.gnugrep
            pkgs.gawk
            pkgs.jq
            pkgs.util-linux
          ];
          text = builtins.readFile ./bench.sh;
        };

      in {
        packages = {
          pg18 = pg18;
          bench = benchScript;
          default = benchScript;
        };

        apps.default = flake-utils.lib.mkApp { drv = benchScript; };
        apps.bench = self.apps.${system}.default;

        devShells.default = pkgs.mkShell {
          packages = [
            pg18
            nucleusPkg
            pkgs.coreutils
            pkgs.gnugrep
            pkgs.gawk
            pkgs.jq
            pkgs.util-linux
          ];
        };
      });
}
