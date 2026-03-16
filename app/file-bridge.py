#!/usr/bin/env python3
"""Session bridge server: file/URL forwarding, clipboard sync, file upload, download watcher.

Runs inside the session container on FILE_BRIDGE_PORT (default 9091).

Endpoints:
  GET  /pending       → JSON array of pending open-requests (xdg-open bridge + downloads)
  GET  /file/<id>     → Download a bridged file by ID
  GET  /ack/<id>      → Acknowledge (remove) a pending item
  GET  /clipboard     → Read the X11 clipboard (session → host)
  POST /clipboard     → Write to the X11 clipboard (host → session)
  POST /upload        → Upload a file into the session home directory
  GET  /health        → Health check
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import unquote, parse_qs

BRIDGE_DIR = Path(os.environ.get("FILE_BRIDGE_DIR", "/tmp/file-bridge"))
PENDING_DIR = BRIDGE_DIR / "pending"
FILES_DIR = BRIDGE_DIR / "files"
UPLOAD_DIR = Path(os.environ.get("SESSION_HOME", "/data/home"))
PORT = int(os.environ.get("FILE_BRIDGE_PORT", "9091"))
HOST = os.environ.get("FILE_BRIDGE_HOST", "0.0.0.0")
DISPLAY = os.environ.get("DISPLAY", ":0")

# Download watcher config
DOWNLOAD_DIR = Path(os.environ.get("SESSION_HOME", "/data/home")) / "Downloads"
DOWNLOAD_WATCH_INTERVAL = float(os.environ.get("DOWNLOAD_WATCH_INTERVAL", "1.5"))

PENDING_DIR.mkdir(parents=True, exist_ok=True)
FILES_DIR.mkdir(parents=True, exist_ok=True)
DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)

SAFE_ID = re.compile(r"^[a-zA-Z0-9._-]+$")
# Track clipboard to detect changes (session → host)
_last_clipboard = ""
_last_clipboard_time = 0

# Track files we've already forwarded (to avoid duplicates)
_forwarded_files = set()
_forwarded_lock = threading.Lock()


def read_x_clipboard():
    """Read text from the X11 clipboard using xclip or xsel."""
    for cmd in [
        ["xclip", "-selection", "clipboard", "-o"],
        ["xsel", "--clipboard", "--output"],
    ]:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=2,
                env={**os.environ, "DISPLAY": DISPLAY},
            )
            if result.returncode == 0:
                return result.stdout.decode("utf-8", errors="replace")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return ""


def write_x_clipboard(text):
    """Write text to the X11 clipboard using xclip or xsel."""
    data = text.encode("utf-8")
    for cmd in [
        ["xclip", "-selection", "clipboard", "-i"],
        ["xsel", "--clipboard", "--input"],
    ]:
        try:
            result = subprocess.run(
                cmd,
                input=data,
                capture_output=True,
                timeout=2,
                env={**os.environ, "DISPLAY": DISPLAY},
            )
            if result.returncode == 0:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return False


def bridge_file(filepath):
    """Copy a file into the bridge and create a pending entry for host download."""
    filepath = Path(filepath)
    if not filepath.is_file():
        return None

    # Generate stable ID from path + mtime + size
    stat = filepath.stat()
    key = f"{filepath}:{stat.st_mtime}:{stat.st_size}"
    file_id = hashlib.sha256(key.encode()).hexdigest()[:16]

    # Check if already forwarded
    with _forwarded_lock:
        if key in _forwarded_files:
            return None
        _forwarded_files.add(key)

    # Copy file to bridge
    ext = filepath.suffix
    bridge_path = FILES_DIR / f"{file_id}{ext}"
    shutil.copy2(filepath, bridge_path)

    # Create pending entry
    entry = {
        "id": file_id,
        "type": "file",
        "name": filepath.name,
        "size": stat.st_size,
        "ts": time.time(),
        "source": "download-watcher",
    }
    (PENDING_DIR / f"{file_id}.json").write_text(json.dumps(entry))
    return file_id


def download_watcher():
    """Watch the Downloads directory for new files and bridge them to the host."""
    import sys
    print(f"Download watcher started: {DOWNLOAD_DIR}", file=sys.stderr, flush=True)

    # Track known files at startup (don't forward existing files)
    known = set()
    if DOWNLOAD_DIR.exists():
        for f in DOWNLOAD_DIR.iterdir():
            if f.is_file() and not f.name.endswith((".part", ".crdownload", ".tmp")):
                stat = f.stat()
                known.add(f"{f}:{stat.st_mtime}:{stat.st_size}")

    while True:
        try:
            time.sleep(DOWNLOAD_WATCH_INTERVAL)
            if not DOWNLOAD_DIR.exists():
                continue

            for f in DOWNLOAD_DIR.iterdir():
                if not f.is_file():
                    continue
                # Skip partial downloads
                if f.name.endswith((".part", ".crdownload", ".tmp", ".download")):
                    continue
                # Skip hidden files
                if f.name.startswith("."):
                    continue

                stat = f.stat()
                key = f"{f}:{stat.st_mtime}:{stat.st_size}"

                # Skip if already known
                if key in known:
                    continue

                # Wait a moment to ensure the file is fully written
                time.sleep(0.5)
                try:
                    new_stat = f.stat()
                    if new_stat.st_size != stat.st_size or new_stat.st_mtime != stat.st_mtime:
                        # File still being written
                        continue
                except FileNotFoundError:
                    continue

                known.add(key)
                fid = bridge_file(f)
                if fid:
                    print(f"Download forwarded: {f.name} ({stat.st_size} bytes) -> {fid}", file=sys.stderr, flush=True)

        except Exception as e:
            print(f"Download watcher error: {e}", file=sys.stderr, flush=True)
            time.sleep(5)


class BridgeHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json_response(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            return self.rfile.read(length)
        return b""

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    def do_GET(self):
        path = unquote(self.path).split("?")[0].rstrip("/")

        if path == "/pending":
            items = []
            for f in sorted(PENDING_DIR.glob("*.json")):
                try:
                    items.append(json.loads(f.read_text()))
                except Exception:
                    pass
            self._json_response(200, items)

        elif path.startswith("/file/"):
            file_id = path[6:]
            if not SAFE_ID.match(file_id):
                self._json_response(400, {"error": "invalid id"})
                return
            matches = list(FILES_DIR.glob(f"{file_id}*"))
            if not matches:
                self._json_response(404, {"error": "not found"})
                return
            fpath = matches[0]
            try:
                data = fpath.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(data)))
                self.send_header(
                    "Content-Disposition",
                    f'attachment; filename="{fpath.name}"',
                )
                self._cors_headers()
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                self._json_response(500, {"error": str(e)})

        elif path.startswith("/ack/"):
            file_id = path[5:]
            if not SAFE_ID.match(file_id):
                self._json_response(400, {"error": "invalid id"})
                return
            (PENDING_DIR / f"{file_id}.json").unlink(missing_ok=True)
            for f in FILES_DIR.glob(f"{file_id}*"):
                f.unlink(missing_ok=True)
            self._json_response(200, {"ok": True})

        elif path == "/clipboard":
            global _last_clipboard, _last_clipboard_time
            text = read_x_clipboard()
            changed = text != _last_clipboard
            if changed:
                _last_clipboard = text
                _last_clipboard_time = time.time()
            self._json_response(200, {
                "text": text,
                "changed": changed,
                "ts": _last_clipboard_time,
            })

        elif path == "/health":
            self._json_response(200, {"ok": True})

        else:
            self._json_response(404, {"error": "not found"})

    def do_POST(self):
        path = unquote(self.path).split("?")[0].rstrip("/")

        if path == "/clipboard":
            body = self._read_body()
            try:
                data = json.loads(body)
                text = data.get("text", "")
            except (json.JSONDecodeError, AttributeError):
                text = body.decode("utf-8", errors="replace")
            global _last_clipboard
            _last_clipboard = text
            ok = write_x_clipboard(text)
            self._json_response(200, {"ok": ok})

        elif path == "/upload":
            body = self._read_body()
            # Parse multipart or raw upload
            content_type = self.headers.get("Content-Type", "")
            filename = "upload"
            file_data = body

            if "multipart/form-data" in content_type:
                # Simple multipart parsing
                boundary = content_type.split("boundary=")[-1].strip()
                parts = body.split(f"--{boundary}".encode())
                for part in parts:
                    if b"filename=" in part:
                        # Extract filename
                        header_end = part.find(b"\r\n\r\n")
                        if header_end < 0:
                            continue
                        headers_raw = part[:header_end].decode("utf-8", errors="replace")
                        fn_match = re.search(r'filename="([^"]+)"', headers_raw)
                        if fn_match:
                            filename = fn_match.group(1)
                        file_data = part[header_end + 4:]
                        # Remove trailing \r\n
                        if file_data.endswith(b"\r\n"):
                            file_data = file_data[:-2]
                        break
            else:
                # Raw upload — get filename from query or header
                qs = parse_qs(unquote(self.path).split("?", 1)[-1] if "?" in self.path else "")
                filename = qs.get("filename", [self.headers.get("X-Filename", "upload")])[0]

            # Sanitize filename
            filename = Path(filename).name
            if not filename or filename.startswith("."):
                filename = "upload"

            target = UPLOAD_DIR / filename
            target.write_bytes(file_data)
            self._json_response(200, {
                "ok": True,
                "path": str(target),
                "size": len(file_data),
            })

        elif path.startswith("/ack/"):
            # Allow POST for ack too
            file_id = path[5:]
            if not SAFE_ID.match(file_id):
                self._json_response(400, {"error": "invalid id"})
                return
            (PENDING_DIR / f"{file_id}.json").unlink(missing_ok=True)
            for f in FILES_DIR.glob(f"{file_id}*"):
                f.unlink(missing_ok=True)
            self._json_response(200, {"ok": True})

        else:
            self._json_response(404, {"error": "not found"})


def main():
    import sys

    # Start download watcher in background thread
    watcher = threading.Thread(target=download_watcher, daemon=True)
    watcher.start()

    try:
        server = HTTPServer((HOST, PORT), BridgeHandler)
        print(f"File bridge listening on {HOST}:{PORT}", file=sys.stderr, flush=True)
        server.serve_forever()
    except OSError as e:
        print(f"File bridge failed to start: {e}", file=sys.stderr, flush=True)
        sys.exit(1)
    except Exception as e:
        print(f"File bridge error: {e}", file=sys.stderr, flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
