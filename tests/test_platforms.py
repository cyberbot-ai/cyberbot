"""Platform selection must not infer unsupported coverage or execute OS metadata."""

import io
import json
import unittest
from contextlib import ExitStack
from unittest.mock import patch, Mock
from collectors.bundle import namespace


class LinuxPlatformsTests(unittest.TestCase):
    def setUp(self):
        self.n = namespace()

    def platform(self, distro, like="", manager="dpkg", init="systemd"):
        markers = {
            "dpkg": "/var/lib/dpkg/status",
            "rpm": "/usr/lib/sysimage/rpm",
            "apk": "/lib/apk/db/installed",
            "pacman": "/var/lib/pacman/local",
        }
        commands = {
            "dpkg": "dpkg-query",
            "rpm": "rpm",
            "apk": "apk",
            "pacman": "pacman",
        }
        with ExitStack() as stack:
            stack.enter_context(
                patch.dict(
                    self.n,
                    {
                        "linux_os_release": lambda: {
                            "ID": distro,
                            "ID_LIKE": like,
                            "VERSION_ID": "1",
                        },
                        "linux_command": lambda name: (
                            "/usr/bin/" + name
                            if name
                            in (
                                commands.get(manager),
                                "systemctl" if init == "systemd" else "rc-status",
                            )
                            else None
                        ),
                    },
                )
            )
            stack.enter_context(
                patch.object(
                    self.n["os"].path,
                    "exists",
                    side_effect=lambda p: p == markers.get(manager),
                )
            )
            stack.enter_context(
                patch.object(
                    self.n["os"].path,
                    "isdir",
                    side_effect=lambda p: p
                    == {"systemd": "/run/systemd/system", "openrc": "/run/openrc"}.get(
                        init
                    ),
                )
            )
            stack.enter_context(
                patch.object(
                    self.n["os"].path,
                    "isfile",
                    side_effect=lambda p: p in ("/proc/stat", "/proc/meminfo"),
                )
            )
            return self.n["linux_platform"]()

    def test_family_identity_and_capabilities_are_independent(self):
        for distro, family, manager in [
            ("debian", "debian", "dpkg"),
            ("ubuntu", "debian", "dpkg"),
            ("rocky", "rhel", "rpm"),
            ("fedora", "rhel", "rpm"),
            ("opensuse-leap", "suse", "rpm"),
            ("arch", "arch", "pacman"),
            ("alpine", "alpine", "apk"),
            ("gentoo", "generic", None),
        ]:
            with self.subTest(distro=distro):
                p = self.platform(distro, manager=manager)
                self.assertEqual(p["family"], family)
                self.assertEqual(p["packageManager"], manager or "unknown")
                self.assertEqual(
                    p["packageAdapter"], "dpkg" if manager == "dpkg" else "unsupported"
                )
                self.assertEqual(
                    p["advisoryProvider"],
                    distro if distro in ("ubuntu", "debian") else "unsupported",
                )
                self.assertLess(len(json.dumps(p)), 1024)
        p = self.platform("custom", like="rhel debian", manager="dpkg", init="openrc")
        self.assertEqual(p["family"], "rhel")
        self.assertEqual(p["packageAdapter"], "dpkg")
        self.assertEqual(p["advisoryProvider"], "unsupported")
        self.assertEqual(p["serviceAdapter"], "unsupported")
        # Known ID wins even if ID_LIKE contradicts it.
        self.assertEqual(self.platform("debian", like="rhel")["family"], "debian")
        self.assertEqual(
            self.platform("ubuntu", manager=None)["advisoryProvider"], "unsupported"
        )

    def test_missing_native_client_does_not_select_a_foreign_package_database(self):
        with (
            patch.dict(
                self.n,
                {
                    "linux_os_release": lambda: {"ID": "rocky"},
                    "linux_command": lambda name: (
                        "/usr/bin/dpkg-query" if name == "dpkg-query" else None
                    ),
                },
            ),
            patch.object(
                self.n["os"].path,
                "exists",
                side_effect=lambda p: p
                in ("/var/lib/dpkg/status", "/usr/lib/sysimage/rpm"),
            ),
        ):
            platform = self.n["linux_platform"]()
            self.assertEqual(platform["packageManager"], "rpm")
            self.assertEqual(platform["packageAdapter"], "unsupported")
        with (
            patch.dict(
                self.n,
                {
                    "linux_os_release": lambda: {"ID": "ubuntu"},
                    "linux_command": lambda name: None,
                },
            ),
            patch.object(
                self.n["os"].path,
                "exists",
                side_effect=lambda p: p == "/var/lib/dpkg/status",
            ),
        ):
            platform = self.n["linux_platform"]()
            self.assertEqual(platform["packageManager"], "dpkg")
            self.assertEqual(platform["packageAdapter"], "unsupported")
            self.assertEqual(platform["advisoryProvider"], "unsupported")

    def test_os_release_precedence_fallback_limits_and_no_execution(self):
        def read(path, **kwargs):
            if path == "/etc/os-release":
                raise FileNotFoundError()
            return io.StringIO('ID=alpine\nID_LIKE="debian rhel"\n')

        with patch("builtins.open", side_effect=read):
            self.assertEqual(self.n["linux_os_release"]()["ID"], "alpine")
        with (
            patch(
                "builtins.open",
                return_value=io.StringIO(
                    'ID=debian\nID=ubuntu\nPRETTY_NAME="SECRET"\nVERSION_ID="$(touch /tmp/unsafe)"\n'
                ),
            ) as opened,
            patch.object(self.n["subprocess"], "run") as command,
        ):
            parsed = self.n["linux_os_release"]()
            self.assertEqual(parsed["ID"], "ubuntu")
            self.assertEqual(self.n["linux_token"](parsed["VERSION_ID"]), "unknown")
            self.assertNotIn("PRETTY_NAME", parsed)
            opened.assert_called_once()
            command.assert_not_called()
        with patch("builtins.open", return_value=io.StringIO("x" * 16385)):
            self.assertEqual(self.n["linux_os_release"](), {})
        with patch("builtins.open", side_effect=PermissionError()) as opened:
            self.assertEqual(self.n["linux_os_release"](), {})
            opened.assert_called_once()  # Do not mask unreadable /etc by using another file.

    def test_foreign_package_manager_never_runs_dpkg(self):
        p = self.platform("rocky", manager="rpm")
        with (
            patch.dict(self.n, {"linux_platform": lambda: p}),
            patch.object(self.n["subprocess"], "Popen") as command,
        ):
            with self.assertRaisesRegex(ValueError, "package_adapter_unsupported"):
                self.n["package_rows"]()
            command.assert_not_called()
        self.assertEqual(
            self.n["linux_services"](dict(p, serviceAdapter="unsupported")),
            ([], ["services_adapter_unsupported"]),
        )

    def test_log_layouts_are_fixed_and_do_not_duplicate_auth(self):
        with patch.object(self.n["os"].path, "isfile", return_value=False):
            rhel = self.n["linux_log_paths"]({"family": "rhel"})
            debian = self.n["linux_log_paths"]({"family": "debian"})
        self.assertEqual(rhel["auth"], "/var/log/secure")
        self.assertEqual(rhel["syslog"], "/var/log/messages")
        self.assertEqual(debian["auth"], "/var/log/auth.log")
        self.assertEqual(len(set(rhel.values())), len(rhel))
        # The actual shared log pipeline uses the selected layout, including cursor handling.
        fake = Mock()
        fake.journal.return_value = False
        fake.bytes_read = 0
        fake.started = 0
        fake.gaps = []
        with patch.dict(
            self.n, {"LogAnalysis": lambda r: fake, "linux_log_paths": lambda: rhel}
        ):
            self.n["analyze_logs"]({})
        self.assertEqual(
            [c.args for c in fake.file.call_args_list],
            [(key, rhel[key]) for key in ("auth", "fail2ban", "syslog", "kern")],
        )

    def test_systemd_units_deduplicate_aliases_and_ignore_untrusted_names(self):
        unit = b"Id=redis.service\nLoadState=loaded\nActiveState=active\n\n"
        reply = Mock(
            stdout=unit
            + unit
            + b"Id=secret.service\nLoadState=loaded\nActiveState=active",
            returncode=0,
        )
        with (
            patch.dict(self.n, {"linux_command": lambda name: "/usr/bin/systemctl"}),
            patch.object(self.n["subprocess"], "run", return_value=reply) as command,
        ):
            services, missing = self.n["linux_services"]({"serviceAdapter": "systemd"})
            self.assertEqual(services, [{"name": "redis.service", "state": "active"}])
            self.assertEqual(missing, [])
            self.assertNotIn("shell", command.call_args.kwargs)
            self.assertIn("httpd", command.call_args.args[0])
