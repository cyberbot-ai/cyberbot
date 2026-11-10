# Changelog

## 0.12.0

- Poll each server over one SSH command at the shared interval, with a single refresh button for metrics, services, logs, and packages.
- Check the server’s APT cache when affected packages are known.

## 0.11.0

- Search for servers by name or SSH address in the Library's server filters.

## 0.10.2

- Show a matching log excerpt with its source and timestamp under findings in the Logs tab.

## 0.10.1

- Give the local OpenSSH control socket more time to respond under load and keep slow connections available for reuse.

## 0.10.0

- Set alert thresholds for built-in resource, service, and log checks across the fleet, per server, or per service connection.

## 0.9.1

- Retry temporary SSH connection failures, limit concurrent handshakes, and show failed metric refreshes on the affected server.

## 0.9.0

- Show the Servers page as a list only. The card view and the view switch are removed.

## 0.8.0

- Copy one APT command for multiple fixable findings across all pages of a server's vulnerabilities tab.

## 0.7.3

- Ask for one-time approval before reversible repairs to security configuration and show the risk and recovery limits in a red warning.

## 0.7.2

- Keep AI action approvals valid when unrelated files appear in local SSH directories, and recheck the full SSH scope before running approved commands.

## 0.7.1

- Align the fleet Console with the page header, separate the command field and results from the scrollbar, and keep the server picker and AI tab usable in narrow windows.

## 0.7.0

- Search individual incidents and incident groups by title, evidence, check, server name or address, status, severity, or identifier.

## 0.6.2

- Center the Incidents page, restore padding inside incident group rows, and keep actions and statuses clear of the scrollbar.

## 0.6.1

- Collect Qdrant metrics from Docker ports published on a verified local host address, and keep checking confirmed service availability on schedule when diagnostics are unavailable.

## 0.6.0

- Raise the configurable limit for concurrent background SSH checks from 16 to 24.

## 0.5.4

- Prefer Ansible inventory domain names when displaying servers and use the configured address for SSH.

## 0.5.3

- Restore SSH polling on Linux hosts that use Python 3.5.

## 0.5.2

- Keep SSH consoles and monitoring connected when unrelated files change alongside local SSH settings.

## 0.5.1

- Restore SSH resource polling on Linux hosts that use Python 3.6 or 3.7.

## 0.5.0

- Connect over SSH automatically when opening a server's Console tab, and reuse the active session when returning to the tab.

## 0.4.0

- In the server list sorted by hostname, show Ansible projects with headings and spacing. Split each inventory by domain and use the inventory folder for hosts without a domain.

## 0.3.2

- Give the server sorting controls a compact text style with an arrow on the active column.

## 0.3.1

- Restore the main window's size and position on macOS, including when it fills the available work area.

## 0.3.0

- Sort the server dashboard by hostname suffix, CPU, load, memory, swap, disk space, or inode usage. Disk sorting uses the fullest mount point.

## 0.2.4

- Collect PgBouncer pool statistics over a verified local socket when automatic diagnostics run as root without a configured role, and report missing credentials and denied access separately.

## 0.2.3

- Correct English labels, statuses, and errors across the app, including SSH commands, AI approvals, monitoring checks, and service metrics.

## 0.2.2

- Label the SSH console button Disconnect to clarify that it ends the session.

## 0.2.1

- Close the AI action approval window automatically after approval succeeds.

## 0.2.0

- Reply in the language of the latest user message in server and fleet AI chats.

## 0.1.1

- Rename the Conversations tab in server details to AI.

## 0.1.0

- First public source release of Cyberbot for macOS.
- Monitor Linux hosts over SSH with resource metrics, systemd status, service connectors, log summaries, and critical Ubuntu and Debian package advisories.
- Investigate related incidents and optionally use a local Codex or Claude CLI with scoped access and approval for eligible actions.
