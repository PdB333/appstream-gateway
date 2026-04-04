# User Permalink Launch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a user open a single app link from the bastion, keep using the same app later, and retain data even if the session pod is recreated.

**Architecture:** Add a public launch path that is authorized by a signed token rather than the admin manager UI. The token resolves to a stable client identity, so storage stays attached to the same user while the session container can still be recreated. Keep the admin dashboard for curation and link creation, but make the user-facing path a direct app permalink.

**Tech Stack:** Node.js HTTP server, existing session token signing, Kubernetes/Docker session backend, manager HTML UI, catalog JSON config, shell session bootstrap.

**Validation rule:** every implementation step ends with a build, deploy, and live test against the production path you actually use.

---

### Task 1: Add a public launch token flow

**Files:**
- Modify: `manager/src/auth.js`
- Modify: `manager/src/server.js`
- Test: `manager/tests/public-launch.test.js`

- [ ] **Step 1: Write the failing test**

```js
import assert from "node:assert/strict";
import { signLaunchToken, verifyLaunchToken } from "../src/auth.js";

const token = signLaunchToken("secret", "vscodium", "alice", 60_000);
assert.equal(verifyLaunchToken("secret", token, "vscodium")?.clientId, "alice");
assert.equal(verifyLaunchToken("secret", token, "obsidian"), null);
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test manager/tests/public-launch.test.js`
Expected: failure because launch token helpers do not exist yet.

- [ ] **Step 3: Write minimal implementation**

Add token helpers in `auth.js` and accept a new public launch route in `server.js` that creates or resumes a session without requiring admin auth when the token is valid.

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test manager/tests/public-launch.test.js`
Expected: PASS.

- [ ] **Step 5: Build and deploy for prod testing**

Run: `docker build -t <your-registry>/appstream-gateway-manager:<tag> . && kubectl apply -f k8s/deployment.yaml -f k8s/image-prepuller.yaml`
Expected: the new manager image is live and reachable from the bastion path you use in production.

- [ ] **Step 6: Commit**

```bash
git add manager/src/auth.js manager/src/server.js manager/tests/public-launch.test.js
git commit -m "feat: add public launch token flow"
```

### Task 2: Make app links persistent per user

**Files:**
- Modify: `manager/src/server.js`
- Modify: `manager/public/index.html`

- [ ] **Step 1: Write the failing test**

```js
assert.match(buildPublicLaunchUrl("vscodium", "user-123"), /clientId=user-123/);
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test manager/tests/public-launch.test.js`
Expected: the helper or the returned URL shape is missing.

- [ ] **Step 3: Write minimal implementation**

Generate a public permalink that carries the app identity and stable client identity. Show a copyable link on app cards so the user can publish it behind the bastion without opening the manager.

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test manager/tests/public-launch.test.js`
Expected: PASS.

- [ ] **Step 5: Build and deploy for prod testing**

Run: `docker build -t <your-registry>/appstream-gateway-manager:<tag> . && kubectl apply -f k8s/deployment.yaml -f k8s/image-prepuller.yaml`
Expected: the public permalink button in the manager produces a live link you can open through the bastion.

- [ ] **Step 6: Commit**

```bash
git add manager/src/server.js manager/public/index.html
git commit -m "feat: add persistent app permalinks"
```

### Task 3: Improve the custom launch preset flow

**Files:**
- Modify: `config/apps.json`
- Modify: `manager/public/index.html`

- [ ] **Step 1: Write the failing test**

```js
assert.ok(apps.some((app) => app.featured));
assert.ok(apps.length >= 10);
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test manager/tests/catalog.test.js`
Expected: the catalog coverage is too small or the preset picker is not wired.

- [ ] **Step 3: Write minimal implementation**

Add more curated apps to the default catalog and let the custom launch form start from an existing app preset instead of always starting from a blank form.

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test manager/tests/catalog.test.js`
Expected: PASS.

- [ ] **Step 5: Build and deploy for prod testing**

Run: `docker build -t <your-registry>/appstream-gateway-manager:<tag> . && kubectl apply -f k8s/deployment.yaml -f k8s/image-prepuller.yaml`
Expected: the custom launch preset picker shows the full catalog in the manager UI.

- [ ] **Step 6: Commit**

```bash
git add config/apps.json manager/public/index.html
git commit -m "feat: expand catalog presets"
```

### Task 4: Keep storage stable across pod recreation

**Files:**
- Modify: `manager/src/server.js`
- Modify: `README.md`

- [ ] **Step 1: Write the failing test**

```js
assert.equal(resolveStorage(appWithPerClient, "user-123").mode, "per-client");
assert.match(resolveStorage(appWithPerClient, "user-123").homeVolumeName, /user-123/);
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test manager/tests/storage.test.js`
Expected: the storage mapping is not covered or is wrong for the permalink flow.

- [ ] **Step 3: Write minimal implementation**

Document that the user-facing permalink depends on a stable client ID and a per-client or shared-app home volume, so data survives pod recreation.

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test manager/tests/storage.test.js`
Expected: PASS.

- [ ] **Step 5: Build and deploy for prod testing**

Run: `docker build -t <your-registry>/appstream-gateway-manager:<tag> . && kubectl apply -f k8s/deployment.yaml -f k8s/image-prepuller.yaml`
Expected: the bastion link returns to the same persisted app data after pod recreation.

- [ ] **Step 6: Commit**

```bash
git add manager/src/server.js README.md
git commit -m "docs: explain persistent session storage"
```
