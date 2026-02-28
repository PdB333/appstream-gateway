# app-web

`app-web` turns compatible Linux desktop applications into isolated browser sessions.
It supports AppImages, preinstalled X11 commands, packaged archives, and other compatible Linux desktop apps.

The stack is:

- one session manager exposed to users
- one container per browser session
- `Xvfb` + `x11vnc` + `websockify` + noVNC inside each session container
- a catalog-driven runtime for AppImages or preinstalled X11 commands
- a pluggable session backend: local Docker or Kubernetes Pods

This keeps each user in a separate desktop session instead of sharing one global VNC desktop.

## What Changed

This version adds:

- isolated per-user sessions instead of a single shared desktop process
- generic application support for AppImages and X11 commands
- a session manager that creates and deletes containers dynamically
- HTTP and WebSocket proxying through the manager so VNC is never exposed directly
- signed session access URLs
- idle session reaping
- CPU/RAM limits per session
- shared AppImage download cache
- non-root application execution inside the session container
- catalog-based configuration for curated production apps
- resumable sessions per client
- optional persistent home volumes per app or per client
- structured manager logs, Prometheus metrics and diagnostics endpoints
- richer application compatibility with AppImages, archives and in-image binaries

## Architecture

1. The `manager` service exposes the public HTTP entrypoint.
2. `POST /api/sessions` asks the manager to create a session container from the generic session image.
3. The session container starts `Xvfb`, `openbox`, `x11vnc`, `websockify`, and the target app.
4. The browser connects to `/sessions/<id>/`, which the manager proxies to the right container.
5. Session traffic is authorized by a signed cookie scoped to that session path.
6. The manager exposes Prometheus metrics on `/metrics`.
7. Session diagnostics and container logs are available through the admin API.

## Kubernetes

The repository now ships Kubernetes manifests in [`k8s/`](k8s/).
Those manifests deploy the manager in `SESSION_BACKEND=kubernetes` mode so it creates session Pods directly through the Kubernetes API instead of using a local Docker socket.

Included resources:

- namespace
- service accounts
- RBAC for Pod creation, inspection and log access
- app catalog `ConfigMap`
- PVCs for shared cache and persistent homes
- manager `Deployment`
- `Service`
- `Ingress`
- `NetworkPolicy`

### Apply

1. Build and push the manager and session images somewhere your cluster can pull them from.
2. Edit [`k8s/deployment.yaml`](k8s/deployment.yaml) and replace the placeholder images and public URL.
3. Create a real secret from [`k8s/secret.example.yaml`](k8s/secret.example.yaml) and save it as `k8s/secret.yaml`.
4. Check that your storage class supports `ReadWriteMany` for the PVCs in [`k8s/pvc.yaml`](k8s/pvc.yaml) if you want shared cache and persistent homes.
5. Apply:

```bash
kubectl apply -f k8s/secret.yaml
kubectl apply -k k8s
```

The manager service is then available through the Ingress in [`k8s/ingress.yaml`](k8s/ingress.yaml).

### Kubernetes Notes

- Session Pods are created in the same namespace as the manager.
- Session diagnostics use `pods/log` and, when available, `metrics.k8s.io`.
- If the cluster has no metrics-server installed, logs and runtime state still work but live CPU/memory stats will be empty.
- Persistent `per-client` and `shared-app` homes rely on the PVC configured through `K8S_SESSION_HOME_CLAIM`.

## Quick Start

1. Copy `.env.example` to `.env`.
2. Set `SESSION_SECRET`.
3. Set `ADMIN_API_TOKEN` if you want the admin APIs protected.
4. Start the stack:

```bash
docker compose up --build
```

5. Open `http://localhost:3000`.

The default catalog contains safe demo apps:

- `xterm`
- `xclock`
- `xeyes`

## Add An AppImage

Edit `config/apps.json` and add an entry like this:

```json
{
  "id": "appimage-example",
  "name": "Example AppImage",
  "description": "An AppImage delivered as an isolated browser session.",
  "source": {
    "type": "appimage-url",
    "url": "https://example.invalid/path/to/example.AppImage",
    "sha256": ""
  },
  "launch": {
    "args": "--no-sandbox",
    "extractAndRun": true
  },
  "resources": {
    "cpuCores": 1,
    "memoryMb": 2048
  },
  "display": {
    "width": 1440,
    "height": 900,
    "depth": 24
  }
}
```

Use `sha256` whenever you control the artifact and want supply-chain verification.

## Session Catalog Format

Each application entry supports:

- `id`: stable slug
- `name`: display name
- `description`: optional description
- `source.type`: `command`, `appimage-url`, `appimage-file`, `binary-path`, or `archive-url`
- `source.command`: shell command for preinstalled apps
- `source.url`: AppImage URL
- `source.sha256`: optional AppImage checksum
- `source.path`: path to an AppImage or binary already present in the image
- `source.archiveEntrypoint`: relative executable path inside an extracted archive
- `source.archiveFormat`: `auto`, `zip`, or `tar`
- `launch.args`: raw CLI args appended to the app launch
- `launch.extractAndRun`: enables `--appimage-extract-and-run`
- `launch.preLaunchCommand`: command executed before the application starts
- `launch.workingDirectory`: working directory used for the launched app
- `launch.healthcheckPath`: HTTP path used by the manager readiness probe
- `resources.cpuCores`: CPU quota
- `resources.memoryMb`: memory limit
- `display.width|height|depth`: virtual screen size
- `storage.mode`: `ephemeral`, `per-client`, or `shared-app`
- `session.resume`: allows the manager to reopen an existing session for the same client/app
- `env`: extra environment variables injected into the session

## Observability

The manager now exposes:

- structured JSON logs on stdout
- Prometheus metrics on `/metrics`
- `GET /api/overview` for dashboard metrics and recent manager events
- `GET /api/sessions/<id>/diagnostics` for runtime state, recent session events and container logs

Diagnostics include:

- launch duration
- readiness probe count
- runtime inspect state
- recent container logs
- last known CPU and memory usage when available

## User Experience

The dashboard now includes:

- a persistent `clientId` stored in the browser
- automatic session resume for compatible apps
- favorites stored locally
- app search/filter by name, tags and categories
- richer custom launch form for multiple source types
- in-dashboard diagnostics and runtime log viewing

For persistent settings, use `storage.mode: per-client` on apps that should keep their home directory between sessions.

## Production Notes

This repository is designed for production-oriented deployments, but production still means operating discipline:

- put the manager behind HTTPS
- set `SECURE_COOKIES=true`
- set a strong `SESSION_SECRET`
- set `ADMIN_API_TOKEN`
- keep `ALLOW_CUSTOM_APPS=false` unless you explicitly trust the admins using it
- curate `config/apps.json` instead of letting users supply arbitrary binaries
- restrict the Docker socket to the manager only
- monitor and prune stale session containers and cache volumes
- scrape `/metrics` from Prometheus or your monitoring stack
- centralize manager JSON logs in your log pipeline

## Limits

This approach works well for many X11/Electron/AppImage applications, but it is still remote desktop delivery:

- latency-sensitive GPU apps will be a poor fit
- audio, USB, webcam, DRM, and advanced window manager integrations may need extra work
- every session consumes RAM and CPU, so sizing matters

## Files

- `Dockerfile`: generic session image
- `app/entrypoint.sh`: session bootstrap for GUI apps
- `app/public/index.html`: noVNC entry page
- `manager/`: session manager and proxy
- `config/apps.json`: curated application catalog
