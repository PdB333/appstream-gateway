import test from "node:test";
import assert from "node:assert/strict";

import {
  createSessionTimings,
  noteSessionInspection,
  finalizeSessionTimings,
} from "../src/session-timings.js";

test("tracks pending and running phases separately before readiness", () => {
  const timings = createSessionTimings(1000);

  noteSessionInspection(
    timings,
    {
      State: {
        Pending: true,
        Running: false,
      },
    },
    4000
  );

  noteSessionInspection(
    timings,
    {
      State: {
        Pending: false,
        Running: true,
      },
    },
    11000
  );

  finalizeSessionTimings(timings, 15000);

  assert.equal(timings.pendingDurationMs, 10000);
  assert.equal(timings.runningDurationMs, 4000);
  assert.equal(timings.launchDurationMs, 14000);
});

test("increments readiness probes while preserving first transition timestamps", () => {
  const timings = createSessionTimings(200);

  noteSessionInspection(
    timings,
    {
      State: {
        Pending: true,
        Running: false,
      },
    },
    1200
  );

  noteSessionInspection(
    timings,
    {
      State: {
        Pending: true,
        Running: false,
      },
    },
    2200
  );

  noteSessionInspection(
    timings,
    {
      State: {
        Pending: false,
        Running: true,
      },
    },
    3200
  );

  noteSessionInspection(
    timings,
    {
      State: {
        Pending: false,
        Running: true,
      },
    },
    4200
  );

  assert.equal(timings.readinessProbeCount, 4);
  assert.equal(timings.firstPendingAt, 200);
  assert.equal(timings.firstRunningAt, 3200);
});
