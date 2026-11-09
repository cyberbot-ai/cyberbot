"""Validate and update the versions shipped together in a Cyberbot release."""

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"


def version_tuple(value):
    if not re.fullmatch(VERSION, value):
        raise ValueError(f"Invalid release version: {value!r}")
    return tuple(map(int, value.split(".")))


def version_fields():
    for path in ("package.json", "package-lock.json", "src-tauri/tauri.conf.json"):
        yield path, r'^  "version": "([^"]+)"'
    yield "package-lock.json", r'^    "": \{\n      "name": "cyberbot",\n      "version": "([^"]+)"'
    for directory, name in (("src-tauri", "cyberbot"), ("check-runner", "cyberbot-check-runner")):
        yield f"{directory}/Cargo.toml", rf'^\[package\]\nname = "{name}"\nversion = "([^"]+)"'
        yield f"{directory}/Cargo.lock", rf'^\[\[package\]\]\nname = "{name}"\nversion = "([^"]+)"'


def read_versions(replacement=None):
    version = json.loads((ROOT / "package.json").read_text())["version"]
    version_tuple(version)
    files = {}
    for path, pattern in version_fields():
        source = files.get(path)
        if source is None:
            source = (ROOT / path).read_text()
        matches = list(re.finditer(pattern, source, re.MULTILINE))
        if len(matches) != 1 or matches[0][1] != version:
            raise ValueError(f"{path} must contain exactly one matching version for each Cyberbot field ({version})")
        if replacement is not None:
            start, end = matches[0].span(1)
            source = source[:start] + replacement + source[end:]
        files[path] = source
    return version, files


def release_notes(version):
    changelog = (ROOT / "CHANGELOG.md").read_text()
    sections = list(re.finditer(r"^## (.+)$", changelog, re.MULTILINE))
    if not sections or sections[0][1] != version or sum(h[1] == version for h in sections) != 1:
        raise ValueError(f"CHANGELOG.md must begin with one release section headed '## {version}'")
    end = sections[1].start() if len(sections) > 1 else len(changelog)
    notes = changelog[sections[0].end():end].strip()
    if not notes:
        raise ValueError(f"CHANGELOG.md has no notes for {version}")
    return notes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("check")
    bump = subcommands.add_parser("bump")
    bump.add_argument("part", choices=("major", "minor", "patch"))
    args = parser.parse_args()
    current, _ = read_versions()
    if args.command == "check":
        release_notes(current)
        print(current)
        return
    # Catch an unfinished previous bump before advancing again.
    release_notes(current)
    parts = list(version_tuple(current))
    index = ("major", "minor", "patch").index(args.part)
    parts[index] += 1
    parts[index + 1:] = [0] * (2 - index)
    replacement = ".".join(map(str, parts))
    _, files = read_versions(replacement)
    for path, source in files.items():
        (ROOT / path).write_text(source)
    print(f"{current} -> {replacement}. Add '## {replacement}' to CHANGELOG.md.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as exc:
        sys.exit(str(exc))
