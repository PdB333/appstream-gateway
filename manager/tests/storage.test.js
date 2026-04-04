import test from "node:test";
import assert from "node:assert/strict";

import { resolveStorage } from "../src/storage.js";

const defaults = { storageMode: "ephemeral" };
const prefix = "app-web-session";

test("per-client storage stays tied to the same client and app", () => {
  const app = {
    id: "vscodium",
    storage: { mode: "per-client" },
  };

  const storage = resolveStorage(app, "user-123", defaults, prefix);

  assert.equal(storage.mode, "per-client");
  assert.match(storage.homeVolumeName, /^app-web-session-home-user-123-vscodium$/);
});

test("shared-app storage uses a single app-scoped volume", () => {
  const app = {
    id: "obsidian",
    storage: { mode: "shared-app" },
  };

  const storage = resolveStorage(app, "user-123", defaults, prefix);

  assert.equal(storage.mode, "shared-app");
  assert.equal(storage.homeVolumeName, "app-web-session-home-shared-obsidian");
});

test("missing client id falls back to ephemeral storage for per-client apps", () => {
  const app = {
    id: "vscodium",
    storage: { mode: "per-client" },
  };

  const storage = resolveStorage(app, "", defaults, prefix);

  assert.deepEqual(storage, { mode: "ephemeral", homeVolumeName: "" });
});
