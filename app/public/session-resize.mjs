export function scheduleViewportResizeBurst(queueResize, startDelay = 0) {
  const initialDelay = Math.max(0, Number(startDelay) || 0);
  const fire = (immediate) => queueResize(undefined, undefined, immediate);

  if (initialDelay === 0) {
    fire(true);
  } else {
    setTimeout(() => fire(true), initialDelay);
  }

  setTimeout(() => fire(false), initialDelay + 300);
  setTimeout(() => fire(false), initialDelay + 1000);
}
