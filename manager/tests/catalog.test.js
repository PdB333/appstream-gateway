import test from "node:test";
import assert from "node:assert/strict";

import { loadCatalog } from "../src/catalog.js";

const defaults = {
  cpuCores: 1,
  memoryMb: 2048,
  width: 1440,
  height: 900,
  depth: 24,
  sessionTtlMs: 2 * 60 * 60 * 1000,
  storageMode: "ephemeral",
  resumeSessions: true,
};

test("firefox prelaunch command clears stale profile locks", async () => {
  const catalog = await loadCatalog(new URL("../../config/apps.json", import.meta.url), defaults);
  const firefox = catalog.get("firefox");

  assert.ok(firefox, "firefox should exist in the catalog");
  assert.match(
    firefox.launch.preLaunchCommand,
    /find \/data\/home\/\.mozilla\/firefox .*parentlock/i
  );
});
