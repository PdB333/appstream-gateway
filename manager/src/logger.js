export function createEventStore(limit = 200) {
  const entries = [];

  return {
    push(entry) {
      entries.push(entry);
      if (entries.length > limit) {
        entries.splice(0, entries.length - limit);
      }
      return entry;
    },
    list(max = limit) {
      return entries.slice(-max);
    },
  };
}

export function createLogger({ service, eventStore }) {
  return function log(level, event, fields = {}) {
    const entry = {
      ts: new Date().toISOString(),
      level,
      service,
      event,
      ...fields,
    };

    if (eventStore) {
      eventStore.push(entry);
    }

    const line = JSON.stringify(entry);
    if (level === "error" || level === "warn") {
      console.error(line);
    } else {
      console.log(line);
    }

    return entry;
  };
}
