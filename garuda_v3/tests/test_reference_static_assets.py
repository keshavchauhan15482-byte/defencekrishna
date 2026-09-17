from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVER = (ROOT / "garuda_v3" / "server.py").read_text(encoding="utf-8")
INDEX = (ROOT / "garuda_v3" / "ui" / "index.html").read_text(encoding="utf-8")


def test_reference_homepage_assets_are_served_by_local_server():
    required = {
        "/pixel.css": "pixel.css",
        "/reference.css": "reference.css",
        "/reference-live.js": "reference-live.js",
    }
    for url, filename in required.items():
        assert f"'{url}':('{filename}'" in SERVER or f'"{url}":("{filename}"' in SERVER
        assert f'href="{url}"' in INDEX or f'src="{url}"' in INDEX


def test_reference_assets_exist_on_disk():
    ui = ROOT / "garuda_v3" / "ui"
    for filename in ("pixel.css", "reference.css", "reference-live.js"):
        path = ui / filename
        assert path.is_file()
        assert path.stat().st_size > 0
