# Appstream Gateway

`appstream-gateway` turns compatible Linux desktop applications into isolated browser sessions.
It supports AppImages, preinstalled X11 commands, packaged archives, and other compatible Linux desktop apps.

The stack is:

- one session manager exposed to users
- one container per browser session
- `xpra` with its built-in HTML5 client inside each session container
- a catalog-driven runtime for AppImages or preinstalled X11 commands
- a pluggable session backend: local Docker or Kubernetes Pods

This keeps each user in a separate desktop session instead of sharing one global VNC desktop.

## Features

- **Isolated per-user sessions** — each browser tab gets its own container with a virtual desktop
- **Generic application support** — AppImages, archives (tar/zip), in-image binaries, X11 commands
- **Dynamic session management** — containers created and destroyed on demand via HTTP API
- **Signed session URLs** — VNC traffic is never exposed directly; the manager proxies everything
- **Bidirectional clipboard** — copy/paste between host browser and session container
- **File upload via drag & drop** — drop files onto the browser to upload into the session
- **xdg-open bridge** — URLs and files opened inside the session are forwarded to the host browser
- **Dynamic resize** — session display follows the browser window size
- **Local cursor mode** — use your native browser cursor instead of the VNC-rendered one
- **Fullscreen mode** — immersive full-screen desktop experience (F11)
- **Collapsible HUD** — toolbar auto-hides, toggle with Ctrl+Shift+H
- **Idle session reaping** — unused sessions are automatically cleaned up
- **CPU/RAM limits** — per-session resource controls
- **Shared download cache** — AppImages are downloaded once and cached across sessions
- **Resumable sessions** — reconnect to your existing session from the same browser
- **Persistent home volumes** — per-client or per-app storage modes
- **Catalog-based configuration** — curated production apps via `config/apps.json`
- **Structured logging** — JSON logs on stdout, Prometheus metrics on `/metrics`
- **Kubernetes support** — deploy sessions as Pods instead of Docker containers

## Architecture

1. The `manager` service exposes the public HTTP entrypoint.
2. `POST /api/sessions` asks the manager to create a session container from the generic session image.
3. The session container starts `xpra` and the target app.
4. The browser connects to `/sessions/<id>/`, which the manager proxies to the Xpra HTML5 session.
5. Session traffic is authorized by a signed cookie scoped to that session path.
6. The manager exposes Prometheus metrics on `/metrics`.
7. Session diagnostics and container logs are available through the admin API.

## Quick Start

1. Copy `.env.example` to `.env`.
2. Set `SESSION_SECRET`.
3. Set `ADMIN_API_TOKEN` if you want the admin APIs protected.
4. Leave `PUBLIC_BASE_URL` empty to auto-detect the current host, or set it explicitly behind a proxy/public domain.
5. Start the stack:

```bash
docker compose up --build
```

6. Open the manager on the host or domain you exposed.

The default catalog includes demo apps (`xterm`, `xclock`, `xeyes`) and production apps like VSCodium, Firefox, Brave, Obsidian, Joplin, Logseq, and Krita.

## Included Applications

| App | Type | Category |
|-----|------|----------|
| Terminal (xterm) | command | debug / utility |
| XClock | command | demo |
| XEyes | command | demo |
| VSCodium | AppImage | development / editor |
| Obsidian | AppImage | productivity / notes |
| Joplin | AppImage | productivity / notes |
| Logseq | AppImage | productivity / knowledge |
| Krita | AppImage | graphics / creative |
| Firefox | archive (tar) | internet / browser |
| Brave Browser | archive (zip) | internet / browser |
| Lens Desktop | AppImage (local) | devops / kubernetes |

## Add An Application

Edit `config/apps.json` and add an entry. Three source types are supported:

### AppImage from URL

```json
{
  "id": "my-app",
  "name": "My App",
  "source": {
    "type": "appimage-url",
    "url": "https://example.com/MyApp.AppImage",
    "sha256": ""
  },
  "launch": {
    "args": "--no-sandbox",
    "extractAndRun": true
  },
  "resources": { "cpuCores": 2, "memoryMb": 4096 },
  "display": { "width": 1440, "height": 900, "depth": 24 }
}
```

### Archive from URL (tar.bz2, tar.gz, zip)

```json
{
  "id": "firefox",
  "name": "Firefox",
  "source": {
    "type": "archive-url",
    "url": "https://download.mozilla.org/?product=firefox-latest-ssl&os=linux64&lang=en-US",
    "archiveEntrypoint": "firefox/firefox",
    "archiveFormat": "auto"
  },
  "launch": { "args": "--no-remote" },
  "resources": { "cpuCores": 2, "memoryMb": 4096 },
  "display": { "width": 1440, "height": 900, "depth": 24 }
}
```

### Preinstalled command

```json
{
  "id": "xterm",
  "name": "Terminal",
  "source": {
    "type": "command",
    "command": "xterm -fa 'DejaVu Sans Mono' -fs 11"
  }
}
```

## Session Catalog Format

Each application entry supports:

| Field | Description |
|-------|-------------|
| `id` | Stable slug used in URLs and storage |
| `name` | Display name |
| `description` | Optional description shown in the dashboard |
| `featured` | Show prominently in the dashboard |
| `categories` | Array of category tags for filtering |
| `tags` | Array of search tags |
| `source.type` | `command`, `appimage-url`, `appimage-file`, `binary-path`, or `archive-url` |
| `source.command` | Shell command (for `command` type) |
| `source.url` | Download URL (for `appimage-url` and `archive-url`) |
| `source.sha256` | Optional checksum for supply-chain verification |
| `source.path` | Filesystem path (for `appimage-file` and `binary-path`) |
| `source.archiveEntrypoint` | Relative path to the executable inside the archive |
| `source.archiveFormat` | `auto`, `zip`, or `tar` |
| `source.archiveStripComponents` | Number of leading path components to strip |
| `launch.args` | CLI args appended to the app command |
| `launch.extractAndRun` | Pre-extract AppImage for better GTK compatibility |
| `launch.preLaunchCommand` | Command executed before the app starts |
| `launch.workingDirectory` | Working directory for the app |
| `launch.healthcheckPath` | HTTP path for the manager readiness probe |
| `resources.cpuCores` | CPU quota |
| `resources.memoryMb` | Memory limit in MB |
| `display.width` | Virtual screen width |
| `display.height` | Virtual screen height |
| `display.depth` | Color depth (16, 24, or 32) |
| `storage.mode` | `ephemeral`, `per-client`, or `shared-app` |
| `session.resume` | Allow reconnecting to existing sessions |
| `env` | Extra environment variables for the session |

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Shift+H` | Toggle HUD toolbar visibility |
| `F11` | Toggle fullscreen mode |

## Session Bridge

The session container runs a lightweight HTTP bridge server for host↔session integration:

- **Clipboard sync** — bidirectional clipboard between browser and session
- **File upload** — drag & drop files onto the browser to upload them into `/data/home`
- **xdg-open bridge** — URLs opened inside the session (e.g. clicking links in VSCodium) are forwarded to your host browser
- **File download** — files passed to `xdg-open` inside the session are downloaded to your host

## Kubernetes

The repository ships Kubernetes manifests in [`k8s/`](k8s/).
Those manifests deploy the manager in `SESSION_BACKEND=kubernetes` mode so it creates session Pods directly through the Kubernetes API instead of using a local Docker socket.

Included resources: namespace, service accounts, RBAC, app catalog ConfigMap, PVCs, manager Deployment, Service, Ingress, NetworkPolicy.

### Apply

1. Build and push the manager and session images somewhere your cluster can pull them from.
2. Edit [`k8s/deployment.yaml`](k8s/deployment.yaml) and replace the placeholder images and public URL.
3. Create a real secret from [`k8s/secret.example.yaml`](k8s/secret.example.yaml).
4. Check that your storage class supports `ReadWriteMany` for the PVCs.
5. Apply:

```bash
kubectl apply -f k8s/secret.yaml
kubectl apply -k k8s
```

## Observability

- **Structured JSON logs** on stdout (manager and session containers)
- **Prometheus metrics** on `/metrics` (session count, launch duration, etc.)
- **Dashboard overview** via `GET /api/overview`
- **Session diagnostics** via `GET /api/sessions/<id>/diagnostics` (runtime state, logs, CPU/memory)

## Production Notes

- Put the manager behind HTTPS and set `SECURE_COOKIES=true`
- Set a strong `SESSION_SECRET` and `ADMIN_API_TOKEN`
- Keep `ALLOW_CUSTOM_APPS=false` unless you trust the admins
- Curate `config/apps.json` — don't let users supply arbitrary binaries
- Restrict the Docker socket to the manager only
- Monitor and prune stale session containers and cache volumes
- Scrape `/metrics` from Prometheus

## Limits

This approach works well for many X11/Electron/AppImage applications, but it is still application streaming over Xpra:

- Latency-sensitive GPU apps will be a poor fit
- Audio, USB, webcam, DRM, and advanced window manager integrations may need extra work
- Every session consumes RAM and CPU, so sizing matters

## Files

| Path | Description |
|------|-------------|
| `Dockerfile` | Generic session image |
| `app/entrypoint.sh` | Session bootstrap (Xpra, app launch, bridges) |
| `app/public/index.html` | Legacy noVNC client kept for reference |
| `app/file-bridge.py` | Session bridge server (clipboard, upload, xdg-open) |
| `app/xdg-open-bridge.sh` | xdg-open override that forwards to the bridge |
| `manager/` | Session manager, proxy, and API server |
| `config/apps.json` | Curated application catalog |
| `k8s/` | Kubernetes manifests |
| `docker-compose.yml` | Local development stack |
