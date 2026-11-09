# Changelog

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
