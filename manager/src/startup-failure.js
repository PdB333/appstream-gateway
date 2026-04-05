export function extractLaunchStage(logTail) {
  if (!logTail) {
    return "";
  }

  let stage = "";
  for (const line of String(logTail).split(/\r?\n/)) {
    const match = line.match(/"event":"launch_stage".*"message":"([^"]+)"/);
    if (match) {
      stage = match[1];
    }
  }

  return stage;
}

export function buildStartupFailureMessage(message, logTail) {
  const stage = extractLaunchStage(logTail);
  if (!logTail && !stage) {
    return message;
  }

  const parts = [];
  if (stage) {
    parts.push(`Launch stage: ${stage}`);
  }
  parts.push(message);
  if (logTail) {
    parts.push("");
    parts.push("Last container logs:");
    parts.push(logTail);
  }

  return parts.join("\n");
}
