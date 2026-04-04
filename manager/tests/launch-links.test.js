import test from "node:test";
import assert from "node:assert/strict";

import { signLaunchToken, verifyLaunchToken } from "../src/auth.js";

test("launch token roundtrips app and client identity", () => {
  const token = signLaunchToken("secret", "vscodium", "alice", 60_000);
  const payload = verifyLaunchToken("secret", token);

  assert.deepEqual(payload, {
    appId: "vscodium",
    clientId: "alice",
  });
});

test("launch token rejects mismatched app ids", () => {
  const token = signLaunchToken("secret", "vscodium", "alice", 60_000);

  assert.equal(verifyLaunchToken("secret", token, "obsidian"), null);
});

