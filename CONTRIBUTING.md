# Contributing to Cyberbot

Switch to `master` before editing and commit changes directly there. Describe the behavior you changed, how to reproduce it, and which checks you ran. Use fictional or redacted hostnames, inventory files, and logs in issues and examples.

## Local development

Use macOS with Xcode Command Line Tools, Node.js 22.22.2 or a newer 22.x release, stable Rust with `rustfmt`, and Python 3. Docker is needed for the Linux and SSH integration tests.

| Command | Purpose |
| --- | --- |
| `make deps` | Install Node dependencies from the lockfile. |
| `make dev` | Run the desktop app with a development frontend. |
| `make web-dev` | Preview the frontend with fictional data. |
| `make build` | Build the native app at `src-tauri/target/release/bundle/macos/Cyberbot.app`. |
| `make check` | Check versions, build the frontend, run local tests, and verify Rust formatting. |
| `make test-collector-linux` | Run collector tests in a network-isolated Linux container. |
| `make test-ssh` | Exercise SSH and rsync against a disposable Docker fixture. |
| `make test-actions` | Exercise Linux isolation and supported action paths against a disposable Docker fixture without a model. |

Use `make help` for focused checks. The [layout fixture](tests/layout/README.md) exercises real components with extreme values. Follow the [interface guidelines](DESIGN.md) for UI changes and the [connector contract](docs/CONNECTORS.md) when extending service coverage. Test any live model integration separately with a test account and disposable hosts. Provider calls can consume paid usage.

## Versions and releases

Run `make bump-version BUMP=patch` for a bug fix, `BUMP=minor` for a feature, or `BUMP=major` for a breaking change. Add a new `## X.Y.Z` section immediately below the changelog title, with user-facing notes in English. Commit the versions, notes, and change together. Documentation and maintenance changes without product impact can keep the current version.

`make version-check` validates the manifests, lockfiles, and current changelog entry. GitHub Actions checks pull requests and pushes to `master`. After a successful push with a newer version, it publishes one GitHub release for the pushed tip and its notes. Rerun a failed workflow from its Actions page to retry that commit. GitHub supplies the source archives.
