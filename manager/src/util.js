import crypto from "node:crypto";

export function parseBoolean(value, defaultValue = false) {
  if (value === undefined || value === null || value === "") {
    return defaultValue;
  }

  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}

export function parseInteger(value, defaultValue) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : defaultValue;
}

export function parseFloatNumber(value, defaultValue) {
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) ? parsed : defaultValue;
}

export function parseDurationMs(value, defaultValue) {
  if (!value) {
    return defaultValue;
  }

  if (/^\d+$/.test(String(value))) {
    return Number.parseInt(String(value), 10);
  }

  const match = String(value).trim().match(/^(\d+)(ms|s|m|h|d)$/i);
  if (!match) {
    return defaultValue;
  }

  const amount = Number.parseInt(match[1], 10);
  const unit = match[2].toLowerCase();
  const multipliers = {
    ms: 1,
    s: 1000,
    m: 60_000,
    h: 3_600_000,
    d: 86_400_000,
  };

  return amount * multipliers[unit];
}

export function slugify(value, fallback = "app") {
  const normalized = String(value || fallback)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);

  return normalized || fallback;
}

export function createSessionId() {
  return crypto.randomBytes(6).toString("hex");
}

export function json(response, statusCode, payload, headers = {}) {
  response.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    ...headers,
  });
  response.end(JSON.stringify(payload, null, 2));
}

export function text(response, statusCode, body, headers = {}) {
  response.writeHead(statusCode, {
    "content-type": "text/plain; charset=utf-8",
    "cache-control": "no-store",
    ...headers,
  });
  response.end(body);
}

export async function readJsonBody(request, maxBytes = 64 * 1024) {
  const chunks = [];
  let total = 0;

  for await (const chunk of request) {
    total += chunk.length;
    if (total > maxBytes) {
      throw new Error("Request body too large");
    }
    chunks.push(chunk);
  }

  if (chunks.length === 0) {
    return {};
  }

  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

export function parseCookies(cookieHeader = "") {
  const output = {};

  for (const part of cookieHeader.split(";")) {
    const trimmed = part.trim();
    if (!trimmed) {
      continue;
    }

    const separatorIndex = trimmed.indexOf("=");
    if (separatorIndex === -1) {
      continue;
    }

    const key = trimmed.slice(0, separatorIndex).trim();
    const value = trimmed.slice(separatorIndex + 1).trim();
    output[key] = decodeURIComponent(value);
  }

  return output;
}

export function serializeCookie(name, value, options = {}) {
  const attributes = [`${name}=${encodeURIComponent(value)}`];

  if (options.maxAge !== undefined) {
    attributes.push(`Max-Age=${Math.floor(options.maxAge)}`);
  }
  if (options.path) {
    attributes.push(`Path=${options.path}`);
  }
  if (options.httpOnly !== false) {
    attributes.push("HttpOnly");
  }
  if (options.sameSite) {
    attributes.push(`SameSite=${options.sameSite}`);
  }
  if (options.secure) {
    attributes.push("Secure");
  }

  return attributes.join("; ");
}

export function buildBaseUrl(request, configuredBaseUrl) {
  if (configuredBaseUrl) {
    return configuredBaseUrl.replace(/\/+$/, "");
  }

  const forwardedProto = request.headers["x-forwarded-proto"];
  const protocol = Array.isArray(forwardedProto)
    ? forwardedProto[0]
    : forwardedProto || "http";
  const host = request.headers["x-forwarded-host"] || request.headers.host || "localhost";

  return `${protocol}://${host}`.replace(/\/+$/, "");
}

export function msToIso(value) {
  return new Date(value).toISOString();
}

export function computeExpiry(lastActivityAt, ttlMs) {
  return lastActivityAt + ttlMs;
}

export function formatDockerName(prefix, sessionId) {
  return `${prefix}-${sessionId}`;
}
