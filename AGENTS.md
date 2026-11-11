# Cyberbot agent instructions

- Read the relevant public documentation and inspect the working tree before editing. Preserve unrelated user changes.
- Switch to `master` before editing and make all commits directly on it.
- Use scoped Vue styles. Keep shared design tokens on the app container and avoid global selectors and deep style overrides.
- For each completed bug fix, bump the patch version. For each feature, bump the minor version. For a breaking change, bump the major version. Run `make bump-version BUMP=patch` (or `minor` or `major`) and add an English entry under the new version in [CHANGELOG.md](CHANGELOG.md). Include both in the same commit as the change. Documentation-only and maintenance changes without product impact may keep the existing version.
- Before pushing, check the version against the latest `origin/master`. If another change used your version, rebase and bump again. GitHub Actions creates releases and tags from pushes to `master`.
- Run the checks relevant to the change before making a separate Git commit with a descriptive message for each completed feature or fix. See [CONTRIBUTING.md](CONTRIBUTING.md).
- Use Evgeniy Udodov <1926460+flrnull@users.noreply.github.com> for this maintainer's public commits. Keep secrets, temporary files, and unrelated changes out of commits.
