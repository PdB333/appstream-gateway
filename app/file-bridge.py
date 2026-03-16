#!/usr/bin/env python3
"""Lightweight file/URL bridge for forwarding xdg-open calls to the host browser.

Runs inside the session container on FILE_BRIDGE_PORT (default 9091).
The custom xdg-open script writes pending items here; the noVNC client polls
and opens URLs / downloads files on the host side.

Endpoints:
  GET  /pending    → JSON array of pending open-requests
  GET  /file/<id>  → Download a bridged file by ID
  GET  /ack/<id>   → Acknowledge (remove) a pending item
  GET  /health     → Health check
"""

import json
import os
import re
import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import unquote

BRIDGE_DIR = Path(os.environ.get("FILE_BRIDGE_DIR", "/tmp/file-bridge"))
PENDING_DIR = BRIDGE_DIR / "pending"
FILES_DIR = BRIDGE_DIR / "files"
PORT = int(os.environ.get("FILE_BRIDGE_PORT", "9091"))

PENDING_DIR.mkdir(parents=True, exist_ok=True)
FILES_DIR.mkdir(parents=True, exist_ok=True)

SAFE_ID = re.compile(r"^[a-zA-Z0-9._-]+$")


class BridgeHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silence access logs

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def _json_response(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    def do_GET(self):
        path = unquote(self.path).rstrip("/")

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
            # Find the file (may have original extension appended)
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

        elif path == "/health":
            self._json_response(200, {"ok": True})

        else:
            self._json_response(404, {"error": "not found"})

    do_POST = do_GET  # allow both GET and POST for simplicity


def main():
    server = HTTPServer(("127.0.0.1", PORT), BridgeHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
