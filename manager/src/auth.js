import crypto from "node:crypto";

function toBase64Url(value) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromBase64Url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  return Buffer.from(padded, "base64");
}

function signPayload(secret, payload) {
  const encodedPayload = toBase64Url(JSON.stringify(payload));
  const signature = crypto
    .createHmac("sha256", secret)
    .update(encodedPayload)
    .digest();

  return `${encodedPayload}.${toBase64Url(signature)}`;
}

function verifyPayload(secret, token) {
  if (!token || !token.includes(".")) {
    return null;
  }

  const [encodedPayload, encodedSignature] = token.split(".", 2);
  const expectedSignature = crypto
    .createHmac("sha256", secret)
    .update(encodedPayload)
    .digest();

  const providedSignature = fromBase64Url(encodedSignature);
  if (
    providedSignature.length !== expectedSignature.length ||
    !crypto.timingSafeEqual(providedSignature, expectedSignature)
  ) {
    return null;
  }

  try {
    return JSON.parse(fromBase64Url(encodedPayload).toString("utf8"));
  } catch {
    return null;
  }
}

export function signSessionToken(secret, sessionId, ttlMs) {
  const payload = {
    kind: "session",
    sessionId,
    exp: Date.now() + ttlMs,
  };

  return signPayload(secret, payload);
}

export function verifySessionToken(secret, token, expectedSessionId) {
  const payload = verifyPayload(secret, token);
  if (!payload || payload.kind !== "session") {
    return false;
  }

  if (payload.sessionId !== expectedSessionId) {
    return false;
  }

  return Number.isFinite(payload.exp) && payload.exp > Date.now();
}

export function signLaunchToken(secret, appId, clientId, ttlMs) {
  const payload = {
    kind: "launch",
    appId,
    clientId,
    exp: Date.now() + ttlMs,
  };

  return signPayload(secret, payload);
}

export function verifyLaunchToken(secret, token, expectedAppId = "") {
  const payload = verifyPayload(secret, token);
  if (!payload || payload.kind !== "launch") {
    return null;
  }

  if (expectedAppId && payload.appId !== expectedAppId) {
    return null;
  }

  if (!Number.isFinite(payload.exp) || payload.exp <= Date.now()) {
    return null;
  }

  if (typeof payload.clientId !== "string" || !payload.clientId.trim()) {
    return null;
  }

  return {
    appId: payload.appId,
    clientId: payload.clientId,
  };
}
