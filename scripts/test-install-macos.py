"""Disposable installer fixtures. No real Applications, index, sudo or app launch."""
import os
from pathlib import Path
import plistlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parent.parent
INSTALLER = PROJECT / "scripts/install-macos.sh"


@unittest.skipUnless(sys.platform == "darwin", "macOS bundle/ditto fixtures")
class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cyberbot install ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.apps = self.root / "Test Applications"
        self.apps.mkdir()
        self.source = self.root / "Build with spaces" / "Cyberbot.app"
        self.destination = self.apps / "Cyberbot.app"
        self.events = self.root / "events"
        self.bundle(self.source, "new")

    def bundle(self, path, version, identifier="dev.cyberbot.desktop"):
        (path / "Contents/MacOS").mkdir(parents=True)
        (path / "Contents/Resources").mkdir()
        (path / "Contents/Info.plist").write_bytes(plistlib.dumps({
            "CFBundleIdentifier": identifier,
            "CFBundleExecutable": "cyberbot",
            "CFBundlePackageType": "APPL",
        }))
        exe = path / "Contents/MacOS/cyberbot"
        exe.write_text(f"#!/bin/sh\nprintf launched > {shlex.quote(str(self.root / 'launched'))}\nexit 99\n")
        exe.chmod(0o755)
        (path / f"Contents/Resources/{version}-only").write_text(version)

    def run_install(self, extra="", action="install", **variables):
        harness = f"source {shlex.quote(str(INSTALLER))}\n" + r'''
install_processes() { return "${PROCESS_RESULT:-1}"; }
install_signature() { return "${SIGNATURE_RESULT:-0}"; }
install_register() { printf 'register\n' >> "$EVENTS"; return "${REGISTER_RESULT:-0}"; }
install_import() { printf 'import\n' >> "$EVENTS"; return "${IMPORT_RESULT:-0}"; }
install_find() { printf 'find\n' >> "$EVENTS"; [[ "${INDEX_READY:-1}" == 1 ]] && printf '%s\n' "$APPS/Cyberbot.app"; return 0; }
install_wait() { SECONDS=$((SECONDS + 30)); }
''' + extra + '\ninstall_main "$@"\n'
        env = {**os.environ, "APPS": str(self.apps), "EVENTS": str(self.events), **variables}
        return subprocess.run(["/bin/bash", "-c", harness, "fixture", action, str(self.source), str(self.apps)],
                              env=env, capture_output=True, text=True, timeout=10)

    def assert_clean(self):
        self.assertEqual(list(self.apps.glob(".cyberbot-install*")), [])
        self.assertFalse((self.root / "launched").exists())

    def test_fresh_install_in_space_paths_and_spotlight_without_launch(self):
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.destination / "Contents/Resources/new-only").exists())
        self.assertTrue(os.access(self.destination / "Contents/MacOS/cyberbot", os.X_OK))
        self.assertEqual(self.events.read_text().splitlines(), ["register", "import", "find"])
        self.assertIn("Spotlight: Cyberbot found", result.stdout)
        self.assert_clean()

    def test_update_replaces_whole_bundle_and_preserves_unrelated_data(self):
        self.bundle(self.destination, "old")
        sentinel = self.apps / "unrelated"
        sentinel.write_text("keep")
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.destination / "Contents/Resources/old-only").exists())
        self.assertTrue((self.destination / "Contents/Resources/new-only").exists())
        self.assertEqual(sentinel.read_text(), "keep")
        self.assert_clean()

    def test_copy_failure_leaves_old_bundle_and_cleans_partial_files(self):
        self.bundle(self.destination, "old")
        result = self.run_install('install_copy() { /bin/mkdir "$2"; printf partial > "$2/partial"; return 1; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.destination / "Contents/Resources/old-only").exists())
        self.assertFalse(self.events.exists())
        self.assert_clean()

    def test_failed_replacement_restores_old_bundle(self):
        self.bundle(self.destination, "old")
        result = self.run_install('install_move() { [[ "$1" == */new.app ]] && return 1; /bin/mv "$1" "$2"; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Previous version of Cyberbot restored", result.stderr)
        self.assertTrue((self.destination / "Contents/Resources/old-only").exists())
        self.assertFalse(self.events.exists())
        self.assert_clean()

    def test_failed_rollback_retains_previous_bundle_for_recovery(self):
        self.bundle(self.destination, "old")
        result = self.run_install('install_move() { [[ "$1" == */new.app || "$1" == */previous.app ]] && return 1; /bin/mv "$1" "$2"; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("saved here", result.stderr)
        backups = list(self.apps.glob(".cyberbot-install.*/previous.app/Contents/Resources/old-only"))
        self.assertEqual(len(backups), 1)
        self.assertFalse((self.apps / ".cyberbot-install.lock").exists())

    def test_corrupt_copy_is_rejected_before_old_bundle_moves(self):
        self.bundle(self.destination, "old")
        result = self.run_install('install_copy() { /bin/mkdir "$2"; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.destination / "Contents/Resources/old-only").exists())
        self.assert_clean()

    def test_invalid_build_metadata_or_missing_executable_leaves_old_app(self):
        self.bundle(self.destination, "old")
        info = self.source / "Contents/Info.plist"
        valid = info.read_bytes()
        for contents in [b"not a plist", plistlib.dumps({"CFBundleIdentifier": "example.wrong"})]:
            info.write_bytes(contents)
            result = self.run_install()
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue((self.destination / "Contents/Resources/old-only").exists())
            self.assert_clean()
        info.write_bytes(valid)
        (self.source / "Contents/MacOS/cyberbot").unlink()
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.destination / "Contents/Resources/old-only").exists())
        self.assert_clean()

    def test_completed_rename_with_failed_status_also_restores_previous_app(self):
        self.bundle(self.destination, "old")
        result = self.run_install('install_move() { /bin/mv "$1" "$2" || return 1; [[ "$2" == */previous.app ]] && return 1; return 0; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.destination / "Contents/Resources/old-only").exists())
        self.assert_clean()

    def test_existing_app_with_another_identifier_is_not_replaced(self):
        self.bundle(self.destination, "foreign", "example.other")
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.destination / "Contents/Resources/foreign-only").exists())
        self.assert_clean()

    def test_invalid_new_signature_never_replaces_existing_app(self):
        self.bundle(self.destination, "old")
        result = self.run_install(SIGNATURE_RESULT="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid app signature", result.stderr)
        self.assertTrue((self.destination / "Contents/Resources/old-only").exists())
        self.assert_clean()

    def test_copied_bundle_signature_is_checked_before_replacement(self):
        self.bundle(self.destination, "old")
        result = self.run_install('install_signature() { [[ "$1" == */new.app ]] && return 1; return 0; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.destination / "Contents/Resources/old-only").exists())
        self.assert_clean()

    def test_symlink_including_broken_symlink_is_never_replaced(self):
        for target in [self.source, self.root / "missing"]:
            self.destination.symlink_to(target)
            result = self.run_install()
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(self.destination.is_symlink())
            self.destination.unlink()
        self.assert_clean()

    def test_running_process_or_failed_process_probe_blocks_installation(self):
        for code in ["0", "2"]:
            result = self.run_install(PROCESS_RESULT=code)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(self.destination.exists())
            self.assert_clean()

    def test_app_opened_during_copy_blocks_replacement(self):
        self.bundle(self.destination, "old")
        result = self.run_install('count=0; install_processes() { count=$((count+1)); [[ "$count" -ge 3 ]] && return 0; return 1; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.destination / "Contents/Resources/old-only").exists())
        self.assert_clean()

    def test_root_build_and_non_macos_are_rejected(self):
        for extra in ['install_uid() { printf 0; }', 'install_platform() { printf Linux; }']:
            result = self.run_install(extra, action="check")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(self.destination.exists())

    def test_registration_failure_does_not_undo_successful_copy(self):
        for name in ["REGISTER_RESULT", "IMPORT_RESULT"]:
            result = self.run_install(**{name: "1"})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("App installed", result.stderr)
            self.assertTrue(self.destination.exists())
            shutil.rmtree(self.destination)
        self.assert_clean()

    def test_indexing_delay_is_not_reported_as_missing_installation(self):
        result = self.run_install(INDEX_READY="0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Spotlight is still being updated", result.stdout)
        self.assertTrue(self.destination.exists())
        self.assertLessEqual(self.events.read_text().splitlines().count("find"), 2)

    def test_privilege_phase_only_copies_and_search_runs_as_original_user(self):
        extra = r'''
install_admin_needed() { return 0; }
install_privileged_copy() { printf 'privileged-copy\n' >> "$EVENTS"; install_copy_bundle "$1" "$2"; }
install_register() { [[ "$(id -u)" != 0 ]] || return 1; printf 'register\n' >> "$EVENTS"; }
'''
        result = self.run_install(extra)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events.read_text().splitlines(), ["privileged-copy", "register", "import", "find"])

    def test_another_installation_lock_is_preserved(self):
        (self.apps / ".cyberbot-install.lock").mkdir()
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.apps / ".cyberbot-install.lock").is_dir())
        self.assertFalse(self.destination.exists())


class MakeOrderTests(unittest.TestCase):
    def run_make(self, fail="", parallel=False, dry=False):
        with tempfile.TemporaryDirectory(prefix="cyberbot make install ") as temp:
            root = Path(temp)
            (root / "scripts").mkdir()
            shutil.copyfile(PROJECT / "Makefile", root / "Makefile")
            wrapper = root / "scripts/install-macos.sh"
            wrapper.write_text('''#!/bin/bash
printf '%s\\n' "$1" >> "$ORDER"
if [[ "$1" == check && "${FAIL:-}" == check ]]; then exit 1; fi
if [[ "$1" == install ]]; then test -f "$2/Contents/Info.plist"; fi
''')
            npm = root / "mock npm"
            npm.write_text(f"#!{sys.executable}\n" + '''import os, pathlib, sys
action = 'deps' if sys.argv[1:] == ['ci'] else 'build'
with open(os.environ['ORDER'], 'a') as f: f.write(action+'\\n')
if os.environ.get('FAIL') == action: sys.exit(1)
if action == 'build':
 p=pathlib.Path(os.environ['BUNDLE'])/'Contents/Info.plist'
 p.parent.mkdir(parents=True);p.write_text('fixture')
''')
            npm.chmod(0o755)
            bundle = root / "Build with spaces/Cyberbot.app"
            order = root / "order"
            args = ["make", "--no-print-directory", "install", f"NPM={shlex.quote(str(npm))}", f"APP_BUNDLE={bundle}"]
            if parallel: args.append("-j8")
            if dry: args.append("-n")
            result = subprocess.run(args, cwd=root, env={**os.environ, "ORDER": str(order), "FAIL": fail, "BUNDLE": str(bundle)},
                                    text=True, capture_output=True, timeout=10)
            return result, order.read_text().splitlines() if order.exists() else []

    def test_parallel_make_keeps_preflight_deps_build_install_order(self):
        result, order = self.run_make(parallel=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(order, ["check", "deps", "build", "install"])

    def test_preflight_or_build_failure_never_reaches_install(self):
        for fail, expected in [("check", ["check"]), ("deps", ["check", "deps"]), ("build", ["check", "deps", "build"])]:
            result, order = self.run_make(fail=fail)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(order, expected)

    def test_dry_run_has_no_side_effects(self):
        result, order = self.run_make(dry=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(order, [])
        self.assertLess(result.stdout.index("install-macos.sh check"), result.stdout.index(" ci"))
        self.assertLess(result.stdout.index(" ci"), result.stdout.index("run desktop:build"))
        self.assertLess(result.stdout.index("run desktop:build"), result.stdout.index("install-macos.sh install"))


if __name__ == "__main__":
    unittest.main()
