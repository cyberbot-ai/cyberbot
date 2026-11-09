"""Select a release from a push and publish it after CI passes."""

import argparse
import json
import os
import re
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from version import ROOT, read_versions, release_notes, version_tuple


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def select_tag(sha, before, version):
    # A root commit also covers the initial launch via a history rewrite.
    if len(git("rev-list", "--parents", "-n", "1", sha).split()) == 1 or before == "0" * 40:
        return f"v{version}"
    if not re.fullmatch(r"[0-9a-f]{40}", before):
        raise ValueError("Expected the SHA before the push")
    previous = json.loads(git("show", f"{before}:package.json"))["version"]
    if version_tuple(version) < version_tuple(previous):
        raise ValueError(f"Version moved backwards from {previous} to {version}")
    return f"v{version}" if previous != version else ""


def github_api(path, payload=None):
    repo = os.environ["GITHUB_REPOSITORY"]
    request = Request(
        f"https://api.github.com/repos/{repo}/{path}",
        data=None if payload is None else json.dumps(payload).encode(),
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {os.environ['GH_TOKEN']}",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            return json.load(response)
    except HTTPError as exc:
        if payload is None and exc.code == 404:
            return None
        raise


def verify_tag(tag, sha, *, required=False):
    ref = github_api(f"git/ref/tags/{tag}")
    if ref is None:
        if required:
            raise ValueError(f"GitHub release {tag} has no tag")
        return False
    target = ref["object"]
    while target["type"] == "tag":
        target = github_api(f"git/tags/{target['sha']}")["object"]
    if target["type"] != "commit" or target["sha"] != sha:
        raise ValueError(f"Tag {tag} already points to a different object. Release aborted.")
    return True


def publish(tag, sha, notes):
    tag_exists = verify_tag(tag, sha)
    existing = github_api(f"releases/tags/{tag}")
    if existing is not None:
        verify_tag(tag, sha, required=True)
        if existing["draft"] or existing["prerelease"]:
            raise ValueError(f"Resolve the existing draft or prerelease for {tag} before retrying")
        print(f"{tag} is already published for {sha}")
        return
    if not tag_exists:
        github_api("git/refs", {"ref": f"refs/tags/{tag}", "sha": sha})
    verify_tag(tag, sha, required=True)
    github_api("releases", {
        "tag_name": tag,
        "target_commitish": sha,
        "name": tag,
        "body": notes,
        "draft": False,
        "prerelease": False,
        "make_latest": "legacy",
    })
    verify_tag(tag, sha, required=True)
    print(f"Published {tag} for {sha}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan")
    plan.add_argument("before")
    release = commands.add_parser("publish")
    release.add_argument("tag")
    args = parser.parse_args()
    version, _ = read_versions()
    notes = release_notes(version)
    sha = git("rev-parse", "HEAD")
    if args.command == "plan":
        print(select_tag(sha, args.before, version))
    else:
        if args.tag != f"v{version}" or sha != os.environ["GITHUB_SHA"]:
            raise ValueError("The version or checkout differs from the CI release candidate")
        publish(args.tag, sha, notes)


if __name__ == "__main__":
    try:
        main()
    except (KeyError, ValueError, OSError, URLError, subprocess.CalledProcessError) as exc:
        sys.exit(str(exc))
