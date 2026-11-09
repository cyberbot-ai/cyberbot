# Cyberbot user guide

## Install and connect

Use the [installation steps](../README.md#get-started). Run `make install` as your user. It asks for administrator privileges only if it needs them to copy the finished bundle. Quit Cyberbot from its menu before updating. Closing the window leaves polling active. The app stops polling while your Mac is asleep.

Check that OpenSSH can authenticate to your servers and verify their host keys before importing them. In the **Servers** page, select **Add server**. Enter one address per line. Use `user@host:port` for an explicit user and port, or `user@[2001:db8::10]:2222` for IPv6 with a port. If omitted, the user comes from SSH configuration or your local account. For Ansible, select a [static inventory file](INVENTORY.md). Use a dedicated account with the minimum permissions needed for your checks.

Cyberbot starts polling automatically and writes its versioned collector under `~/.cache/cyberbot` on the remote account. The host needs SSH, rsync, and Python 3. Cyberbot can use compatible host aliases, keys, and jump hosts in your OpenSSH configuration.

## Read the dashboard and investigate incidents

- **Servers** shows resource and service status across your fleet. The first poll after startup or wake establishes fresh status. An unknown or stale reading is shown separately from a healthy result. The polling control at the bottom of the sidebar pauses or resumes collection.
- Open a server for its overview, service panels, logs, vulnerabilities, checks, AI conversations, and interactive SSH console. The service panels show missing permissions and unsupported capabilities alongside the measurements that are available.
- The **Incidents** page groups related episodes and shows their evidence. Use **Mark resolved** to clear an active episode from the dashboard while retaining its history. Recurring bad observations stay suppressed until recovery is confirmed. See [incident groups](INCIDENT_GROUPS.md) for correlation and recovery.
- Enable macOS notifications in Cyberbot settings and grant permission in System Settings if you want incident notifications. The **Activity log** records operations, timing, and results. Retention and storage usage are shown in settings.

### Service, log, and package coverage

Nginx can use an existing `stub_status` endpoint and accessible access or error logs. Response codes, upstream timings, and latency estimates depend on the configured log format and available fields. PostgreSQL can report connections, long-running queries, blocking, replication, and maintenance indicators, subject to diagnostic privileges. See [connectors](CONNECTORS.md) for other services and requirements.

System and SSH log summaries use incremental reading and limited evidence. Source access, rotation, and incomplete samples affect coverage. Package advisory checks cover critical advisories on supported Debian and Ubuntu releases and match installed versions locally. Each affected source package contributes one representative CVE to the active list. Dismissing a package suppresses it until its installed versions change, or until you restore it from the hidden packages list.

The monitoring library lists built-in checks, their sources and operations, and the settings that apply. Configuration inherits from factory defaults through the fleet, server, and service instance. Disabling a check stops new observations and automatic investigations from its evidence. Existing history is retained.

## Use AI investigations

1. Install and authenticate the Codex or Claude CLI with its own login flow.
2. Under **AI → Settings**, select the provider, check CLI compatibility, and choose supported models for the low, medium, and high profiles.
3. Open a server's **AI** tab or an incident and start a manual investigation. An AI run receives access to a fixed server scope and selected monitoring evidence. Provider requests may process information included in that evidence.
4. To run investigations automatically, set the run and token limits, then turn on the **AI** switch. Zero disables the corresponding limit. Limits count UTC days and apply to manual runs as well. The CLI reports token usage asynchronously, so the app's limits may differ from provider billing.

In server and fleet AI chats, the agent follows the language of your latest message. You can switch languages within a conversation.

In a manual conversation, the agent may propose a supported action. Review the target, exact effect, and evidence before approving. Approving until the end of the run keeps the same fixed server scope and each proposed script still goes through risk review. For supported Nginx configuration changes, the app shows the result and offers rollback while the recorded files still match. If the response is lost, verify the saved receipt before deciding what to do next.

User-defined checks use declarative rules over saved metrics. Use the check editor to test the definition with fixtures, preview the results on a server, and enable a reviewed version. Scheduled checks run without invoking the model.

See [architecture and trust boundaries](architecture.md) for storage, MCP access, and action limits.
