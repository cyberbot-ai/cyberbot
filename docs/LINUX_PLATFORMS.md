# Linux platforms

Cyberbot needs SSH, rsync, and Python 3 on the remote host. Its general resource checks read Linux kernel interfaces. Each additional capability depends on the host's utilities, init system, data sources, and permissions.

| Capability | Current coverage |
| --- | --- |
| Host identification | Exact distribution ID and ordered family hints from `os-release`. Profiles cover Debian and Ubuntu, RHEL and related distributions, SUSE, Arch, and Alpine, with a generic fallback. |
| Resource metrics | CPU, memory, swap, load, uptime, filesystem use, and inode use when the kernel exposes the necessary data. |
| Services | systemd. The presence of `systemctl` alone does not establish that systemd is active. |
| Packages | dpkg inventory and the existing APT cache. RPM, APK, and pacman can be recognized without package collection. |
| Critical advisories | Supported, explicitly identified Debian and Ubuntu releases with matching advisory sources. A derivative does not inherit advisory coverage. |
| Logs | Standard paths for known distro families and supported journal sources. Permissions and available files determine coverage. |

The app reports unsupported and incomplete capabilities explicitly. Service connectors have [separate requirements](CONNECTORS.md).

## Adding a platform adapter

- Extend the trusted Python platform modules in `collectors/platforms/`. The app bundles adapters at build time. Read `os-release` as bounded data.
- Normalize service output and missing fields through the existing service contract. For packages, define the manager's inventory and version ordering separately from package transport. Use fixed read-only operations.
- If the adapter adds a capability, update the typed Rust contract in `src-tauri/src/platform.rs` and the frontend coverage display. Exercise missing utilities, missing permissions, contradictory identity hints, and partial results.
- Run `make test-collector-linux` and test on the claimed distributions. Use a host or VM with the real init system for service behavior. Record the verified coverage in this guide.
