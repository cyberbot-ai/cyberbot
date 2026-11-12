# Cyberbot architecture

Cyberbot is a macOS desktop app built with Tauri 2, Rust, and Vue 3. The desktop process coordinates polling, incident evaluation, SQLite storage, and optional AI investigations. The Vue interface reads typed data through Tauri commands. The browser preview uses fictional fixtures.

## From a server to an incident

1. The user adds an SSH endpoint or a [static Ansible inventory](INVENTORY.md). Server identity is local and separate from the endpoint used for access.
2. Rust schedules checks through bounded queues and an OpenSSH ControlMaster pool. The pool sizes itself to the number of distinct SSH configurations in the inventory, with a capacity of 32 to 192. Polling, rsync, and the interactive console reuse compatible connections. Host keys are verified. A busy connection stays available to its active operations while the pool evicts idle connections.
3. The application bundles the Python collector at build time and uses rsync to deploy a content-addressed copy into the remote user's cache. Each routine server poll verifies and runs the collector in one SSH command. The collector streams bounded results for the enabled checks. The activity log stores the transport status and check results in one entry per poll.
4. Rust validates the result and records observations. A metric that cannot be read or is too old remains unknown. Deterministic rules evaluate metrics, logs, connector results, and package advisories. An episode retains its own evidence and identity. [Incident correlation](INCIDENT_GROUPS.md) may link episodes without merging their history.
5. The dashboard and monitoring library show observations, failures, permissions, and coverage. Routine collection and rules work without an AI provider.

[Linux platform adapters](LINUX_PLATFORMS.md) provide runtime identity, package and service capabilities, and log paths. [Service connectors](CONNECTORS.md) collect independent application metrics and keep instance-specific settings and history. Log collectors keep cursors, handle rotation, and retain limited samples. Package checks match critical advisories for supported Ubuntu and Debian releases to installed package versions using distro-specific comparison rules.

## Storage

The default macOS data directory is `~/Library/Application Support/dev.cyberbot.desktop`. Tests can use an isolated directory through `CYBERBOT_DATA_DIR`. SQLite stores settings, inventory, monitoring history, incidents, queue state, and recent reports. Activity logs rotate separately and avoid storing action scripts and full results. Storage settings show usage. The SQLite database, advisory cache, and activity log have separate limits of 1 GiB, 128 MiB, and 30 MiB respectively. Old records are pruned. A change to a server's SSH endpoint can invalidate observations and existing AI access to that target.

History retention uses a shared allowance of 50,000 unprotected service samples across all connector types, for up to seven days. Metrics retain up to 120,000 unprotected samples for up to 30 days. Latest results per server, service instance, log source, or custom check and samples linked as incident evidence are exempt from history pruning. Existing incident expiration still releases evidence for expired closed incidents.

At 900 MiB of occupied SQLite pages, cleanup removes the oldest unprotected service, metric, log, and custom-check history until occupancy reaches 800 MiB. Occupancy excludes freelist pages: SQLite can reuse them without shrinking the file. Settings display this occupied space. Physical compaction is reserved for legacy database files exceeding 1 GiB.

Cleanup persists its phase and pressure state in SQLite. It deletes at most 500 selected history rows per batch, releases the writer lock between batches, and checks a 500-millisecond pass budget between batches. An individual SQL statement or legacy compaction may exceed the pass budget. Routine cleanup runs every five minutes. Unfinished work resumes after five seconds, or after one second under storage pressure. WAL checkpoints run at the size threshold and at the end of each pass. A pinned WAL reader or exhausted removable history delays the next attempt by one minute. Cleanup retries automatically and preserves settings, inventory, active work, and protected evidence.

## AI and trust boundaries

The desktop starts a supported local Codex or Claude process and brokers monitoring access through MCP. Each run receives a frozen server scope. The broker checks the current server identity, endpoint, and scope when handling a request. Local process isolation, bounded calls, and typed tool inputs constrain agent access. The CLI and chosen provider handle authentication and inference. Manual investigations may read selected public HTTPS resources and limited server file evidence when the policy permits it.

Automatic investigations run through a persistent queue. They reserve tokens before execution, deduplicate by incident episode, and respect cooldowns and the configured run budget. Unconfirmed usage holds the reservation and pauses new automatic work until the operator resolves it. The system records usage reported by the CLI and cannot enforce the provider's billing.

### Proposed actions

The action broker validates the frozen scope and candidate script, then requests a separate review from the selected provider's low profile. The approval record is bound to the script, inputs, run, and SSH context. Context changes invalidate it. The broker applies its own policy even after review and approval.

- A matching run approval covers low-risk actions. Manual SSH commands with material or unresolved risks, or whose review is unavailable, require one-time approval. The approval window explains the risk or review failure. Commands with a concrete harmful effect, such as destroying infrastructure data or sending credentials to a separate external recipient, are blocked. Explicitly reading credentials into AI output requires one-time approval. Cyberbot returns SSH output to the AI provider and retains it in the action history.
- Typed actions still require a completed review. Recoverable risks, including targeted repairs to protective configuration, require one-time approval and show the likely effects and recovery limits.
- Read-only investigations use stored evidence and bounded refresh operations. Manual conversations can request supported file operations in allowlisted directories. The worker enforces path, resource, and output limits.
- In-memory Python calculations receive bounded data and run with filesystem, network, and process access blocked. Approved shell execution has its own scope, review, and time and output limits.
- The supported managed Nginx change sets `worker_processes`. It requires the necessary privileges and supported Linux isolation. It validates configuration, checks the original hash, writes atomically, activates the change, and records a receipt. Rollback checks the current file and recorded backup before restoring. When the result is unknown, the app can inspect the receipt without replaying the operation.

Declarative checks are separate from actions. Draft versions are tested with fixtures and isolated execution, previewed before activation, and can be rolled back. The selected version evaluates stored metrics on schedule without an agent.

## Code map

| Component | Responsibility |
| --- | --- |
| `src/` | Vue interface and browser preview |
| `src-tauri/` | Native commands, state, SSH, persistence, and agent policy |
| `collectors/` | Remote Python bundle, platform adapters, and service connectors |
| `check-runner/` | Isolated sidecar for declarative checks |

See [Contributing](../CONTRIBUTING.md) for build and verification commands.
