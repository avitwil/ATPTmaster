"""Desktop launcher: writable data home, free-port pick, background server,
and the native-window / browser-fallback decision. GUI windows are never
opened under test — only the headless pieces are exercised."""
import os
import socket
import unittest
import urllib.request
from pathlib import Path

from atpt import desktop


class DataHomeTest(unittest.TestCase):
    def test_env_override_wins(self):
        home = desktop.data_home({"ATPT_HOME": "/tmp/atpt-custom"})
        self.assertEqual(home, Path("/tmp/atpt-custom"))

    def test_linux_uses_xdg_data_home(self):
        home = desktop.data_home({"HOME": "/home/x"}, platform="linux")
        self.assertEqual(home, Path("/home/x/.local/share/ATPTmaster"))

    def test_linux_respects_xdg_data_home(self):
        env = {"HOME": "/home/x", "XDG_DATA_HOME": "/data"}
        home = desktop.data_home(env, platform="linux")
        self.assertEqual(home, Path("/data/ATPTmaster"))

    def test_macos_uses_application_support(self):
        home = desktop.data_home({"HOME": "/Users/x"}, platform="darwin")
        self.assertEqual(home, Path("/Users/x/Library/Application Support/ATPTmaster"))


class FreePortTest(unittest.TestCase):
    def test_returns_a_bindable_port(self):
        port = desktop.pick_free_port("127.0.0.1")
        self.assertIsInstance(port, int)
        self.assertTrue(0 < port < 65536)
        # Nothing else holds it: we can bind it right now.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.close()


class BackgroundServerTest(unittest.TestCase):
    def test_serves_the_console_then_stops(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            srv = desktop.start_server(Path(d), host="127.0.0.1")
            try:
                self.assertTrue(desktop.wait_until_ready(srv.host, srv.port, timeout=5))
                url = f"http://{srv.host}:{srv.port}/"
                with urllib.request.urlopen(url, timeout=5) as resp:
                    body = resp.read().decode()
                self.assertIn("ATPTmaster Console", body)
            finally:
                srv.stop()
            # After stop the port no longer answers.
            with self.assertRaises(Exception):
                urllib.request.urlopen(
                    f"http://{srv.host}:{srv.port}/", timeout=1
                )


class PrepareHomeTest(unittest.TestCase):
    def test_seeds_modules_and_assets_into_empty_home(self):
        import tempfile

        with tempfile.TemporaryDirectory() as c, tempfile.TemporaryDirectory() as h:
            code_root, home = Path(c), Path(h)
            (code_root / "modules" / "m1").mkdir(parents=True)
            (code_root / "modules" / "m1" / "module.py").write_text("# m1")
            (code_root / "atpt" / "assets").mkdir(parents=True)
            (code_root / "atpt" / "assets" / "logo.png").write_bytes(b"PNG")

            project_dir = desktop.prepare_home(code_root, home)

            self.assertEqual(project_dir, home)
            self.assertTrue((home / "modules" / "m1" / "module.py").is_file())
            self.assertTrue((home / "atpt" / "assets" / "logo.png").is_file())
            self.assertTrue((home / "var").is_dir())

    def test_does_not_overwrite_existing_home_modules(self):
        import tempfile

        with tempfile.TemporaryDirectory() as c, tempfile.TemporaryDirectory() as h:
            code_root, home = Path(c), Path(h)
            (code_root / "modules" / "m1").mkdir(parents=True)
            (code_root / "modules" / "m1" / "module.py").write_text("# fresh")
            (home / "modules" / "m1").mkdir(parents=True)
            (home / "modules" / "m1" / "module.py").write_text("# user-edited")

            desktop.prepare_home(code_root, home)

            self.assertEqual(
                (home / "modules" / "m1" / "module.py").read_text(), "# user-edited"
            )


class OpenWindowTest(unittest.TestCase):
    def test_uses_native_when_available(self):
        calls = []
        result = desktop.open_window(
            "http://x",
            native=lambda url, title: calls.append(("native", url)),
            browser=lambda url: calls.append(("browser", url)),
        )
        self.assertEqual(result, "native")
        self.assertEqual(calls, [("native", "http://x")])

    def test_falls_back_to_browser_when_pywebview_missing(self):
        calls = []

        def no_webview(url, title):
            raise ImportError("no pywebview")

        result = desktop.open_window(
            "http://x",
            native=no_webview,
            browser=lambda url: calls.append(("browser", url)),
        )
        self.assertEqual(result, "browser")
        self.assertEqual(calls, [("browser", "http://x")])


if __name__ == "__main__":
    unittest.main()
