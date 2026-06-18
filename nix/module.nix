{ config, lib, pkgs, ... }:

let
  cfg = config.services.nucleus;
  inherit (lib) mkEnableOption mkOption types mkIf mapAttrs' nameValuePair
    concatStringsSep optional optionalString;

  containerOpts = { name, ... }: {
    options = {
      enable = mkEnableOption "this Nucleus container";

      command = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Command and arguments to run inside the container.";
      };

      rootfs = mkOption {
        type = types.nullOr types.package;
        default = null;
        description = ''
          Nix-built rootfs derivation (e.g. pkgs.buildEnv).
          Mounted read-only as the container filesystem instead of host bind mounts.
        '';
      };

      image = mkOption {
        type = types.nullOr types.package;
        default = null;
        description = ''
          Nix-built Nucleus image derivation produced by nucleus.lib.mkImage.
          Mutually exclusive with rootfs. The module uses the image manifest's
          base rootfs and command unless command is set explicitly.
        '';
      };

      user = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          User name or numeric UID to run the workload as after Nucleus completes
          namespace, mount, and cgroup setup.
        '';
      };

      group = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Group name or numeric GID to run the workload as after setup.
          When omitted, Nucleus uses the primary group for a named user.
        '';
      };

      supplementaryGroups = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Supplementary groups (names or numeric GIDs) for the workload process.";
      };

      memory = mkOption {
        type = types.str;
        example = "512M";
        description = "Memory limit (e.g. 512M, 1G).";
      };

      cpus = mkOption {
        type = types.nullOr types.float;
        default = null;
        description = "CPU core limit.";
      };

      pids = mkOption {
        type = types.int;
        default = 512;
        description = "Maximum number of PIDs.";
      };

      network = mkOption {
        type = types.enum [ "none" "bridge" ];
        default = "bridge";
        description = "Network mode. Production mode forbids 'host'.";
      };

      dns = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "DNS servers for the container. Must be set explicitly for production.";
      };

      natBackend = mkOption {
        type = types.enum [ "auto" "kernel" "userspace" ];
        default = "auto";
        description = "Native bridge NAT backend selection.";
      };

      egressAllow = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "10.0.0.0/8" "192.168.1.0/24" ];
        description = ''
          Allowed egress CIDRs. Combined with egressDomains.
          Production mode always enforces an egress policy (deny-all when both
          egressAllow and egressDomains are empty).
        '';
      };

      egressDomains = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "api.example.com" ];
        description = ''
          Allowed exact egress domains. Nucleus resolves each domain to IPv4
          /32 rules at container startup; wildcard and suffix matching are not
          supported.
        '';
      };

      egressTcpPorts = mkOption {
        type = types.listOf types.port;
        default = [ ];
        description = "Allowed egress TCP destination ports.";
      };

      egressUdpPorts = mkOption {
        type = types.listOf types.port;
        default = [ ];
        description = "Allowed egress UDP destination ports.";
      };

      credentialBroker = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "10.0.42.1:8080";
        description = ''
          Host-side credential broker endpoint in IPv4:PORT form. When set,
          Nucleus installs broker-only egress and rejects direct upstream
          egress allowlists.
        '';
      };

      credentialBrokerNoProxyEnv = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Disable automatic HTTP_PROXY/HTTPS_PROXY injection for
          credentialBroker. Use this when the workload is pointed at the
          broker through provider-specific base URL variables instead.
        '';
      };

      portForwards = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "127.0.0.1:8080:80" "5353:53/udp" ];
        description = "Port forwarding rules (HOST:CONTAINER[/PROTOCOL] or HOST_IP:HOST:CONTAINER[/PROTOCOL]).";
      };

      trustLevel = mkOption {
        type = types.enum [ "trusted" "untrusted" ];
        default = "trusted";
        description = "Workload trust level. 'untrusted' requires gVisor.";
      };

      runtime = mkOption {
        type = types.enum [ "native" "gvisor" ];
        default = "native";
        description = "Container runtime.";
      };

      gvisorPlatform = mkOption {
        type = types.enum [ "systrap" "kvm" "ptrace" ];
        default = "systrap";
        description = "gVisor platform backend when runtime = gvisor.";
      };

      requireKernelLockdown = mkOption {
        type = types.nullOr (types.enum [ "integrity" "confidentiality" ]);
        default = null;
        description = "Require the host kernel to be in at least this lockdown mode.";
      };

      verifyRootfsAttestation = mkOption {
        type = types.bool;
        default = true;
        description = "Verify the rootfs attestation manifest before container start.";
      };

      verifyContextIntegrity = mkOption {
        type = types.bool;
        default = true;
        description = "Verify context contents before the workload runs.";
      };

      seccompLogDenied = mkOption {
        type = types.bool;
        default = true;
        description = "Request kernel logging for denied seccomp decisions when supported.";
      };

      timeNamespace = mkOption {
        type = types.bool;
        default = false;
        description = "Enable Linux time namespace isolation.";
      };

      cgroupNamespace = mkOption {
        type = types.bool;
        default = true;
        description = "Enable Linux cgroup namespace isolation.";
      };

      healthCheck = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "curl -sf http://localhost:8080/health";
        description = "Health check command to run inside the container.";
      };

      healthInterval = mkOption {
        type = types.int;
        default = 30;
        description = "Health check interval in seconds.";
      };

      healthRetries = mkOption {
        type = types.int;
        default = 3;
        description = "Health check failure retries before unhealthy.";
      };

      healthStartPeriod = mkOption {
        type = types.int;
        default = 5;
        description = "Seconds to wait before starting health checks.";
      };

      secrets = mkOption {
        type = types.listOf (types.submodule {
          options = {
            source = mkOption {
              type = types.path;
              description = "Source path (host or Nix store) for the secret.";
            };
            dest = mkOption {
              type = types.str;
              description = "Destination path inside the container.";
            };
          };
        });
        default = [ ];
        description = "Secret files to mount read-only into the container.";
      };

      credentials = mkOption {
        type = types.listOf (types.submodule {
          options = {
            name = mkOption {
              type = types.str;
              description = "Systemd credential name exposed to the unit.";
            };
            source = mkOption {
              type = types.either types.path types.str;
              description = "Credential source passed to LoadCredential or LoadCredentialEncrypted.";
            };
            dest = mkOption {
              type = types.str;
              description = "Destination path inside the container.";
            };
            encrypted = mkOption {
              type = types.bool;
              default = false;
              description = "Use systemd LoadCredentialEncrypted instead of LoadCredential.";
            };
          };
        });
        default = [ ];
        description = "Systemd-managed credentials mounted into the container as secrets.";
      };

      volumes = mkOption {
        type = types.listOf (types.submodule {
          options = {
            source = mkOption {
              type = types.str;
              description = "Host path to bind-mount into the container.";
            };
            dest = mkOption {
              type = types.str;
              description = "Destination path inside the container.";
            };
            readOnly = mkOption {
              type = types.bool;
              default = false;
              description = "Mount the volume read-only.";
            };
            createHostPath = mkOption {
              type = types.bool;
              default = false;
              description = "Create the host path as a directory via systemd-tmpfiles before container start.";
            };
            directoryMode = mkOption {
              type = types.str;
              default = "0750";
              description = "Mode to use when createHostPath = true.";
            };
            user = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = ''
                Owner user to use when createHostPath = true.
                Defaults to the container's `user`, or `root` when unset.
              '';
            };
            group = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = ''
                Owner group to use when createHostPath = true.
                Defaults to the container's `group`, or `root` when unset.
              '';
            };
          };
        });
        default = [ ];
        description = "Host bind volumes to mount into the container.";
      };

      environment = mkOption {
        type = types.attrsOf types.str;
        default = { };
        description = "Environment variables to set in the container.";
      };

      readinessExec = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "curl -sf http://localhost:8080/ready";
        description = ''
          Readiness probe command. Service is ready when this exits 0.
          When sdNotify is true, nucleus sends READY=1 to systemd on probe success.
          Mutually exclusive with readinessTcp and readinessSdNotify.
        '';
      };

      readinessTcp = mkOption {
        type = types.nullOr types.port;
        default = null;
        example = 8080;
        description = ''
          Readiness probe TCP port. Service is ready when this port accepts connections.
          Mutually exclusive with readinessExec and readinessSdNotify.
        '';
      };

      readinessSdNotify = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Readiness probe: the container process sends READY=1 via sd_notify itself.
          Mutually exclusive with readinessExec and readinessTcp.
        '';
      };

      sdNotify = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Enable sd_notify integration for systemd readiness.
          Only enable if the container process (or a readiness probe) sends READY=1.
          When false, systemd uses Type=simple (ready immediately after exec).
        '';
      };

      context = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Context directory to pre-populate in the container.";
      };

      seccompProfile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to a custom seccomp BPF profile (JSON). If set, nucleus loads this instead of its built-in filter.";
      };

      seccompProfileSha256 = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Expected SHA-256 hex digest of the seccomp profile. Nucleus refuses to start if the profile hash doesn't match.";
      };

      capsPolicy = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to capability policy file (TOML). Defines which capabilities to keep/drop.";
      };

      capsPolicySha256 = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Expected SHA-256 hash of the capability policy file.";
      };

      landlockPolicy = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to Landlock filesystem policy file (TOML). Defines per-path access rules.";
      };

      landlockPolicySha256 = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Expected SHA-256 hash of the Landlock policy file.";
      };

      extraArgs = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Extra arguments to pass to the nucleus run command.";
      };
    };
  };

  mkContainerService = name: containerCfg:
    let
      e = lib.escapeShellArg;
      writableVolumeSources = lib.unique (map (v: v.source) (lib.filter (v: !v.readOnly) containerCfg.volumes));
      loadCredentialEntries =
        map (c: "${c.name}:${toString c.source}") (lib.filter (c: !c.encrypted) containerCfg.credentials);
      loadCredentialEncryptedEntries =
        map (c: "${c.name}:${toString c.source}") (lib.filter (c: c.encrypted) containerCfg.credentials);
      imageManifest =
        if containerCfg.image != null
        then builtins.fromJSON (builtins.readFile "${containerCfg.image}/manifest.json")
        else null;
      effectiveRootfs =
        if containerCfg.image != null
        then imageManifest.base.rootfs_path
        else toString containerCfg.rootfs;
      effectiveCommand =
        if containerCfg.command != [ ]
        then containerCfg.command
        else if imageManifest != null
        then imageManifest.config.command
        else [ ];
      nucleusArgs = lib.concatStringsSep " " (
        [
          "--service-mode" "production"
          "--trust-level" (e containerCfg.trustLevel)
          "--memory" (e containerCfg.memory)
          "--pids" (e (toString containerCfg.pids))
          "--network" (e containerCfg.network)
          "--rootfs" (e effectiveRootfs)
          "--name" (e name)
        ]
        ++ lib.optionals (containerCfg.user != null) [ "--user" (e containerCfg.user) ]
        ++ lib.optionals (containerCfg.group != null) [ "--group" (e containerCfg.group) ]
        ++ (lib.concatMap (g: [ "--additional-group" (e g) ]) containerCfg.supplementaryGroups)
        ++ lib.optionals (containerCfg.cpus != null) [ "--cpus" (e (toString containerCfg.cpus)) ]
        ++ optional (containerCfg.runtime == "gvisor") "--runtime gvisor"
        ++ optional (containerCfg.runtime == "gvisor") "--gvisor-platform"
        ++ optional (containerCfg.runtime == "gvisor") (e containerCfg.gvisorPlatform)
        ++ optional containerCfg.sdNotify "--sd-notify"
        ++ optional containerCfg.seccompLogDenied "--seccomp-log-denied"
        ++ optional containerCfg.verifyRootfsAttestation "--verify-rootfs-attestation"
        ++ optional containerCfg.verifyContextIntegrity "--verify-context-integrity"
        ++ optional containerCfg.timeNamespace "--time-namespace"
        ++ optional (!containerCfg.cgroupNamespace) "--disable-cgroup-namespace"
        ++ lib.optionals (containerCfg.requireKernelLockdown != null) [
          "--require-kernel-lockdown" (e containerCfg.requireKernelLockdown)
        ]
        ++ lib.optionals (containerCfg.network == "bridge") [ "--nat-backend" (e containerCfg.natBackend) ]
        ++ (lib.concatMap (d: [ "--dns" (e d) ]) containerCfg.dns)
        ++ (lib.concatMap (c: [ "--egress-allow" (e c) ]) containerCfg.egressAllow)
        ++ (lib.concatMap (d: [ "--egress-domain" (e d) ]) containerCfg.egressDomains)
        ++ (lib.concatMap (p: [ "--egress-tcp-port" (e (toString p)) ]) containerCfg.egressTcpPorts)
        ++ (lib.concatMap (p: [ "--egress-udp-port" (e (toString p)) ]) containerCfg.egressUdpPorts)
        ++ lib.optionals (containerCfg.credentialBroker != null) [ "--credential-broker" (e containerCfg.credentialBroker) ]
        ++ optional containerCfg.credentialBrokerNoProxyEnv "--credential-broker-no-proxy-env"
        ++ (lib.concatMap (p: [ "-p" (e p) ]) containerCfg.portForwards)
        ++ (lib.concatMap (s: [ "--secret" (e "${toString s.source}:${s.dest}") ]) containerCfg.secrets)
        ++ (lib.concatMap (c: [ "--systemd-credential" (e "${c.name}:${c.dest}") ]) containerCfg.credentials)
        ++ (lib.concatMap (v: [ "--volume" (e "${v.source}:${v.dest}:${if v.readOnly then "ro" else "rw"}") ]) containerCfg.volumes)
        ++ (lib.concatLists (lib.mapAttrsToList (k: v: [ "-e" (e "${k}=${v}") ]) containerCfg.environment))
        ++ lib.optionals (containerCfg.readinessExec != null) [ "--readiness-exec" (e containerCfg.readinessExec) ]
        ++ lib.optionals (containerCfg.readinessTcp != null) [ "--readiness-tcp" (e (toString containerCfg.readinessTcp)) ]
        ++ optional containerCfg.readinessSdNotify "--readiness-sd-notify"
        ++ lib.optionals (containerCfg.healthCheck != null) [
          "--health-cmd" (e containerCfg.healthCheck)
          "--health-interval" (e (toString containerCfg.healthInterval))
          "--health-retries" (e (toString containerCfg.healthRetries))
          "--health-start-period" (e (toString containerCfg.healthStartPeriod))
        ]
        ++ lib.optionals (containerCfg.context != null) [ "--context" (e (toString containerCfg.context)) ]
        ++ lib.optionals (containerCfg.seccompProfile != null) [
          "--seccomp-profile" (e (toString containerCfg.seccompProfile))
        ]
        ++ lib.optionals (containerCfg.seccompProfileSha256 != null) [
          "--seccomp-profile-sha256" (e containerCfg.seccompProfileSha256)
        ]
        ++ lib.optionals (containerCfg.capsPolicy != null) [
          "--caps-policy" (e (toString containerCfg.capsPolicy))
        ]
        ++ lib.optionals (containerCfg.capsPolicySha256 != null) [
          "--caps-policy-sha256" (e containerCfg.capsPolicySha256)
        ]
        ++ lib.optionals (containerCfg.landlockPolicy != null) [
          "--landlock-policy" (e (toString containerCfg.landlockPolicy))
        ]
        ++ lib.optionals (containerCfg.landlockPolicySha256 != null) [
          "--landlock-policy-sha256" (e containerCfg.landlockPolicySha256)
        ]
        ++ containerCfg.extraArgs
      );
      commandStr = lib.concatStringsSep " " (map lib.escapeShellArg effectiveCommand);
    in
    assert lib.assertMsg (containerCfg.rootfs != null || containerCfg.image != null)
      "services.nucleus.containers.${name}: set either rootfs or image";
    assert lib.assertMsg (!(containerCfg.rootfs != null && containerCfg.image != null))
      "services.nucleus.containers.${name}: rootfs and image are mutually exclusive";
    assert lib.assertMsg (effectiveCommand != [ ])
      "services.nucleus.containers.${name}: command is required when image manifest command is empty";
    assert lib.assertMsg (imageManifest == null || imageManifest.diff == null)
      "services.nucleus.containers.${name}: image diffs are not yet supported by the NixOS production launcher";
    nameValuePair "nucleus-${name}" {
      description = "Nucleus container: ${name}";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      path = lib.optionals (containerCfg.runtime == "gvisor") [ pkgs.gvisor ]
        ++ lib.optionals (containerCfg.network == "bridge") [ pkgs.iptables pkgs.slirp4netns ];

      serviceConfig = {
        Type = if containerCfg.sdNotify then "notify" else "simple";
        ExecStart = "${cfg.package}/bin/nucleus run ${nucleusArgs} -- ${commandStr}";
        Restart = "on-failure";
        RestartSec = "5s";

        # Journald integration: nucleus already uses tracing, which outputs
        # structured log lines. systemd captures stdout/stderr to journald.
        StandardOutput = "journal";
        StandardError = "journal";
        SyslogIdentifier = "nucleus-${name}";

        # Cgroup delegation: nucleus creates child cgroups for resource limits.
        # Without Delegate=yes, systemd owns the cgroup tree and the runtime's
        # cgroup operations conflict with systemd's controller model.
        # See https://systemd.io/CONTROL_GROUP_INTERFACE/
        Delegate = true;

        # Hardening at the systemd level (defense-in-depth)
        ProtectSystem = "strict";
        ProtectHome = true;
        NoNewPrivileges = false; # nucleus needs to set up namespaces
        LimitNOFILE = 65536;
      } // lib.optionalAttrs (writableVolumeSources != [ ]) {
        ReadWritePaths = writableVolumeSources;
      } // lib.optionalAttrs (loadCredentialEntries != [ ]) {
        LoadCredential = loadCredentialEntries;
      } // lib.optionalAttrs (loadCredentialEncryptedEntries != [ ]) {
        LoadCredentialEncrypted = loadCredentialEncryptedEntries;
      };
    };

  mkTopologyService = name: topoCfg:
    nameValuePair "nucleus-topology-${name}" {
      description = "Nucleus topology: ${name}";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      path = [ pkgs.iptables pkgs.slirp4netns ] ++ lib.optionals (pkgs ? gvisor) [ pkgs.gvisor ];

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${cfg.package}/bin/nucleus compose up ${lib.escapeShellArg (toString topoCfg.configFile)}";
        ExecStop = "${cfg.package}/bin/nucleus compose down ${lib.escapeShellArg (toString topoCfg.configFile)}";
        StandardOutput = "journal";
        StandardError = "journal";
        SyslogIdentifier = "nucleus-topology-${name}";
        Delegate = true;
      };
    };

in
{
  options.services.nucleus = {
    enable = mkEnableOption "Nucleus container runtime for production services";

    package = mkOption {
      type = types.package;
      description = "The nucleus package to use.";
    };

    containers = mkOption {
      type = types.attrsOf (types.submodule containerOpts);
      default = { };
      description = "Declarative Nucleus containers to run as systemd services.";
    };

    topologies = mkOption {
      type = types.attrsOf (types.submodule {
        options = {
          enable = mkEnableOption "this Nucleus topology";

          configFile = mkOption {
            type = types.path;
            description = "Path to the topology TOML file (nucleus compose format).";
          };
        };
      });
      default = { };
      description = ''
        Declarative Nucleus topologies (multi-container stacks).
        Each topology is managed by `nucleus compose up/down`.
      '';
    };
  };

  config = mkIf cfg.enable {
    systemd.tmpfiles.rules = lib.concatMap
      (containerCfg:
        map
          (v:
            let
              ownerUser = if v.user != null then v.user else if containerCfg.user != null then containerCfg.user else "root";
              ownerGroup = if v.group != null then v.group else if containerCfg.group != null then containerCfg.group else "root";
            in
            "d ${v.source} ${v.directoryMode} ${ownerUser} ${ownerGroup} -")
          (lib.filter (v: v.createHostPath) containerCfg.volumes)
      )
      (lib.attrValues (lib.filterAttrs (_: c: c.enable) cfg.containers));

    systemd.services = lib.mapAttrs' mkContainerService
      (lib.filterAttrs (_: c: c.enable) cfg.containers)
    // lib.mapAttrs' mkTopologyService
      (lib.filterAttrs (_: t: t.enable) cfg.topologies);
  };
}
