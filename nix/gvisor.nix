{ gvisor, fetchFromGitHub }:

gvisor.overrideAttrs (old: rec {
  version = "20261116.0";
  # Generated Go tree for the upstream release commit 89cacadae21e.
  src = fetchFromGitHub {
    owner = "google";
    repo = "gvisor";
    rev = "83282de1f21f9ff56941696424d8d9d74e01ee9a";
    hash = "sha256-BQl38sXpgpyKzckqR89vvxA7FW19+TVSx819hKQoxf0=";
  };
  vendorHash = "sha256-TOKSscirbx+/17LYfDdNfoDS8E6aTLMbNAD0lMlqkn8=";
  # The older nixpkgs go.mod tidy patch targets the April dependency graph.
  patches = [ ./patches/gvisor-runsc-real-exe-path.patch ];
  ldflags = old.ldflags ++ [ "-X=gvisor.dev/gvisor/runsc/version.version=release-${version}" ];
  subPackages = old.subPackages ++ [
    "runsc/cmd/sentry" "runsc/cmd/netgofer" "runsc/cmd/metricserver" "runsc/checkpointgofer"
  ];
  postInstall = old.postInstall + ''
    sidecars="$out/bin/gvisor-bin"
    mkdir -p "$sidecars"
    mv "$out/bin/sentry" "$sidecars/gvisor_sentry"
    mv "$out/bin/netgofer" "$sidecars/runsc-netgofer"
    mv "$out/bin/metricserver" "$sidecars/runsc-metric-server"
    mv "$out/bin/checkpointgofer" "$sidecars/"
    # Upstream's three small Linux helpers run without a dynamic loader or libc.
    buildHelper() {
      $CC -Os -fno-pie -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables \
        -fno-unwind-tables -static -nostdlib -nostartfiles -Wl,--build-id=none,--gc-sections,-n,-s \
        "runsc/$1/$1.c" -o "$sidecars/$2"
    }
    buildHelper fdparking runsc-fd-parking
    buildHelper procumounter gvisor-proc-umounter
    buildHelper prewarmer gvisor-sentry-prewarmer
  '';
})
