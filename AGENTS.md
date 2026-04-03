# Agent Workflow

This repo is maintained from `C:\Users\Selat\.kube\appstream-gateway` locally and `/root/appstream-gateway` on the k3s master at `192.168.1.16`.

## Standard Change Flow

When a change affects runtime behavior, browser behavior, Docker image contents, or Kubernetes manifests, follow this order:

1. Edit the code in the local repo.
2. Commit the code change locally.
3. Push the code to GitHub.
4. SSH to `root@192.168.1.16`.
5. Pull the latest repo on `/root/appstream-gateway`.
6. Build the new image on the SSH host.
7. Push the image to `ghcr.io/pdb333/appstream-gateway-session:<new-tag>`.
8. Update the Kubernetes manifests in `/root/appstream-gateway/k8s`.
9. Commit the manifest update on the SSH host.
10. Apply the manifests to k3s.
11. Roll out the manager and image-prepuller.
12. Recreate any stale session pods so they pick up the new session image.
13. Run basic checks after rollout.

## Build And Deploy Rules

- Always use a new image tag per change.
- The session image tag must be propagated to both:
  - `k8s/deployment.yaml`
  - `k8s/image-prepuller.yaml`
- The k3s cluster lives on `192.168.1.16`.
- Prefer the SSH host for build and deploy steps so the running cluster matches the repo state there.
- Do not assume local `kubectl` is connected; verify the SSH host context instead.

## Browser And Viewport Rules

- The default session browser should stay JavaScript-capable and stable.
- `epiphany-browser` is the preferred default browser.
- `netsurf` is only a fallback.
- noVNC should use viewport scaling, not a fake stretched canvas.
- If mouse alignment breaks, check `scaleViewport`, `resizeSession`, and any CSS that forces the canvas to stretch.

## Verification Rules

- After code changes, verify the diff and the repository status.
- After building, verify the image tag that was pushed.
- After updating manifests, verify the live values in k3s.
- After rollout, confirm the manager, image-prepuller, and session pods are on the expected tag.
- If a stale session pod still runs the old image, delete it so a new one starts from the latest tag.

## Remote Commands

Typical SSH host commands:

```bash
cd /root/appstream-gateway
git pull --ff-only
docker build -t ghcr.io/pdb333/appstream-gateway-session:<tag> -f Dockerfile .
docker push ghcr.io/pdb333/appstream-gateway-session:<tag>
kubectl apply -f k8s/deployment.yaml -f k8s/image-prepuller.yaml
kubectl -n app-web rollout status deployment/app-web-manager
kubectl -n app-web rollout status daemonset/app-web-image-prepuller
kubectl -n app-web get pods -o wide
```

If the repo on the SSH host drifts from GitHub, sync GitHub first, then pull again on the host before building.
