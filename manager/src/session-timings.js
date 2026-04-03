export function createSessionTimings(startedAt) {
  return {
    createStartedAt: startedAt,
    readyAt: 0,
    launchDurationMs: 0,
    readinessProbeCount: 0,
    lastProbeAt: 0,
    firstPendingAt: 0,
    firstRunningAt: 0,
    pendingDurationMs: 0,
    runningDurationMs: 0,
  };
}

export function noteSessionInspection(timings, inspection, now) {
  timings.readinessProbeCount += 1;
  timings.lastProbeAt = now;

  if (inspection?.State?.Pending && !timings.firstPendingAt) {
    timings.firstPendingAt = timings.createStartedAt || now;
  }

  if (inspection?.State?.Running && !timings.firstRunningAt) {
    timings.firstRunningAt = now;
  }
}

export function finalizeSessionTimings(timings, readyAt) {
  timings.readyAt = readyAt;
  timings.launchDurationMs = Math.max(0, readyAt - timings.createStartedAt);

  if (timings.firstPendingAt) {
    const pendingEnd = timings.firstRunningAt || readyAt;
    timings.pendingDurationMs = Math.max(0, pendingEnd - timings.firstPendingAt);
  }

  if (timings.firstRunningAt) {
    timings.runningDurationMs = Math.max(0, readyAt - timings.firstRunningAt);
  }

  return timings;
}
