import test from "node:test";
import assert from "node:assert/strict";

import { buildStartupFailureMessage, extractLaunchStage } from "../src/startup-failure.js";

test("extracts the last launch stage from startup logs", () => {
  const logTail = [
    '{"ts":"2026-04-05T09:00:00Z","level":"info","event":"launch_stage","message":"download archive"}',
    '{"ts":"2026-04-05T09:00:01Z","level":"info","event":"launch_stage","message":"extract archive"}',
    'tar (child): xz: Cannot exec: No such file or directory',
  ].join("\n");

  assert.equal(extractLaunchStage(logTail), "extract archive");
});

test("prepends launch stage information to startup failures", () => {
  const logTail = '{"ts":"2026-04-05T09:00:01Z","level":"info","event":"launch_stage","message":"extract archive"}';
  const message = buildStartupFailureMessage("Session exited before becoming ready", logTail);

  assert.match(message, /Launch stage: extract archive/);
  assert.match(message, /Session exited before becoming ready/);
  assert.match(message, /Last container logs:/);
});
