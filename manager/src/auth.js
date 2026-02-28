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

export function signSessionToken(secret, sessionId, ttlMs) {
  const payload = {
    sessionId,
    exp: Date.now() + ttlMs,
  };

  const encodedPayload = toBase64Url(JSON.stringify(payload));
  const signature = crypto
    .createHmac("sha256", secret)
    .update(encodedPayload)
    .digest();

  return `${encodedPayload}.${toBase64Url(signature)}`;
}

export function verifySessionToken(secret, token, expectedSessionId) {
  if (!token || !token.includes(".")) {
    return false;
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
    return false;
  }

  const payload = JSON.parse(fromBase64Url(encodedPayload).toString("utf8"));
  if (payload.sessionId !== expectedSessionId) {
    return false;
  }

  return Number.isFinite(payload.exp) && payload.exp > Date.now();
}
