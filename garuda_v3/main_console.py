"""Serve the actual orange/charcoal console.html as the main Krishna Defence site.

This wraps the existing localhost bridge but guarantees that console.html is the UI surface,
then applies the nationals presentation overlays after the legacy integration assets.
"""
from __future__ import annotations

import json
import os
from http.server import ThreadingHTTPServer
from urllib.parse import urlsplit

from . import legacy_console as legacy

CONSOLE_BUILD = "v132-nationals-console"


def _inject_console() -> bytes:
    html = legacy.CONSOLE.read_text(encoding="utf-8")
    tags = [
        '<link rel="stylesheet" href="/console-integrated.css">',
        '<link rel="stylesheet" href="/console-v131-overlay.css">',
        '<link rel="stylesheet" href="/console-v132-extra.css">',
    ]
    for tag in tags:
        if tag not in html:
            html = html.replace("</head>", tag + "\n</head>")
    scripts = [
        '<script src="/console-integrated.js"></script>',
        '<script src="/console-v131-overlay.js"></script>',
        '<script src="/console-v132-extra.js"></script>',
    ]
    for tag in scripts:
        if tag not in html:
            html = html.replace("</body>", tag + "\n</body>")
    return html.encode("utf-8")


class MainConsoleHandler(legacy.LegacyConsoleHandler):
    server_version = "KrishnaMainConsole/132"

    def do_GET(self) -> None:
        url = urlsplit(self.path)
        if not self._host_ok() or not self._check_origin():
            return self._json(403, {"error": "Local same-origin console only"})
        try:
            if url.path in ("/", "/console.html"):
                return self._send(200, _inject_console(), "text/html; charset=utf-8")
            if url.path == "/console-v131-overlay.js":
                return self._send(200, (legacy.UI / "console-v131-overlay.js").read_bytes(), "application/javascript")
            if url.path == "/console-v131-overlay.css":
                return self._send(200, (legacy.UI / "console-v131-overlay.css").read_bytes(), "text/css")
            if url.path == "/console-v132-extra.js":
                return self._send(200, (legacy.UI / "console-v132-extra.js").read_bytes(), "application/javascript")
            if url.path == "/console-v132-extra.css":
                return self._send(200, (legacy.UI / "console-v132-extra.css").read_bytes(), "text/css")
            if url.path == "/health":
                return self._json(200, {
                    "status": "alive",
                    "engine": legacy.ENGINE,
                    "console_build": CONSOLE_BUILD,
                    "surface": "console.html",
                    "runtime_bundle": legacy.BUNDLE_METADATA,
                })
            return super().do_GET()
        except ValueError as exc:
            return self._json(422, {"error": str(exc)})
        except (RuntimeError, KeyError, json.JSONDecodeError) as exc:
            return self._json(502, {"error": str(exc)})


class MainConsoleServer(ThreadingHTTPServer):
    daemon_threads = True


def main() -> None:
    # All supported console launch commands use the unified runtime.
    from .integrated_server import main as integrated_main
    integrated_main()


if __name__ == "__main__":
    main()
