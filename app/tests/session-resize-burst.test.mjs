import assert from 'node:assert/strict';
import { scheduleViewportResizeBurst } from '../public/session-resize.mjs';

const originalSetTimeout = globalThis.setTimeout;
const timers = [];
const calls = [];

try {
  globalThis.setTimeout = (fn, delay) => {
    timers.push(delay);
    return originalSetTimeout(() => fn(), 0);
  };

  scheduleViewportResizeBurst((width, height, immediate) => {
    calls.push({ width, height, immediate });
  }, 200);

  await new Promise((resolve) => originalSetTimeout(resolve, 20));

  assert.deepStrictEqual(timers, [200, 500, 1200]);
  assert.deepStrictEqual(calls, [
    { width: undefined, height: undefined, immediate: true },
    { width: undefined, height: undefined, immediate: false },
    { width: undefined, height: undefined, immediate: false },
  ]);
} finally {
  globalThis.setTimeout = originalSetTimeout;
}

