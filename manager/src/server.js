import http from "node:http";
import net from "node:net";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { signSessionToken, verifySessionToken } from "./auth.js";
import { loadCatalog, normalizeApp } from "./catalog.js";
import { DockerClient, DockerError } from "./docker-api.js";
import { KubernetesClient } from "./kubernetes-api.js";
import { createEventStore, createLogger } from "./logger.js";
import {
  buildBaseUrl,
  computeExpiry,
  createSessionId,
  formatDockerName,
  json,
  msToIso,
  parseBoolean,
  parseCookies,
  parseDurationMs,
  parseFloatNumber,
  parseInteger,
  readJsonBody,
  serializeCookie,
  slugify,
  text,
} from "./util.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.resolve(__dirname, "../public");

const config = {
  port: parseInteger(process.env.PORT, 3000),
  publicBaseUrl: process.env.PUBLIC_BASE_URL || "",
  appCatalogPath: process.env.APP_CATALOG_PATH || "/app/config/apps.json",
  dockerSocketPath: process.env.DOCKER_SOCKET_PATH || "/var/run/docker.sock",
  sessionBackend: process.env.SESSION_BACKEND || "docker",
  sessionImage: process.env.SESSION_IMAGE || "local/app-web-session:latest",
  sessionNetwork: process.env.SESSION_NETWORK || "app-web-sessions",
  sessionInternalPort: parseInteger(process.env.SESSION_INTERNAL_PORT, 8080),
  k8sNamespace: process.env.K8S_NAMESPACE || "",
  k8sSessionPodServiceAccount: process.env.K8S_SESSION_POD_SERVICE_ACCOUNT || "default",
  k8sSessionImagePullPolicy: process.env.K8S_SESSION_IMAGE_PULL_POLICY || "IfNotPresent",
  k8sSessionCacheClaim: process.env.K8S_SESSION_CACHE_CLAIM || "",
  k8sSessionHomeClaim: process.env.K8S_SESSION_HOME_CLAIM || "",
  sessionSecret: process.env.SESSION_SECRET || "insecure-development-secret",
  sessionTokenTtlMs: parseDurationMs(process.env.SESSION_TOKEN_TTL, 7 * 24 * 60 * 60 * 1000),
  defaultSessionTtlMs: parseDurationMs(process.env.DEFAULT_SESSION_TTL, 2 * 60 * 60 * 1000),
  sessionReadyTimeoutMs: parseDurationMs(process.env.SESSION_READY_TIMEOUT, 90 * 1000),
  reaperIntervalMs: parseDurationMs(process.env.REAPER_INTERVAL, 30 * 1000),
  secureCookies: parseBoolean(process.env.SECURE_COOKIES, false),
  adminApiToken: process.env.ADMIN_API_TOKEN || "",
  allowCustomApps: parseBoolean(process.env.ALLOW_CUSTOM_APPS, false),
  containerPrefix: slugify(process.env.SESSION_CONTAINER_PREFIX || "app-web-session", "session"),
  cacheVolumeName: process.env.SESSION_CACHE_VOLUME || "app-web-cache",
  defaultCpuCores: parseFloatNumber(process.env.DEFAULT_CPU_CORES, 1),
  defaultMemoryMb: parseInteger(process.env.DEFAULT_MEMORY_MB, 2048),
  defaultScreenWidth: parseInteger(process.env.DEFAULT_SCREEN_WIDTH, 1440),
  defaultScreenHeight: parseInteger(process.env.DEFAULT_SCREEN_HEIGHT, 900),
  defaultScreenDepth: parseInteger(process.env.DEFAULT_SCREEN_DEPTH, 24),
  defaultStorageMode: process.env.DEFAULT_STORAGE_MODE || "ephemeral",
  resumeSessions: parseBoolean(process.env.RESUME_SESSIONS, true),
  stoppedSessionGraceMs: parseDurationMs(process.env.STOPPED_SESSION_GRACE, 5 * 60 * 1000),
  sessionLogTail: parseInteger(process.env.SESSION_LOG_TAIL, 200),
  maxManagerEvents: parseInteger(process.env.MAX_MANAGER_EVENTS, 300),
  maxSessionEvents: parseInteger(process.env.MAX_SESSION_EVENTS, 120),
};

const defaults = {
  cpuCores: config.defaultCpuCores,
  memoryMb: config.defaultMemoryMb,
  width: config.defaultScreenWidth,
  height: config.defaultScreenHeight,
  depth: config.defaultScreenDepth,
  sessionTtlMs: config.defaultSessionTtlMs,
  storageMode: config.defaultStorageMode,
  resumeSessions: config.resumeSessions,
};

const runtimeClient =
  config.sessionBackend === "kubernetes"
    ? new KubernetesClient({
        namespace: config.k8sNamespace || undefined,
      })
    : new DockerClient(config.dockerSocketPath);
const sessions = new Map();
let appCatalog = new Map();

const managerEventStore = createEventStore(config.maxManagerEvents);
const log = createLogger({
  service: "app-web-manager",
  eventStore: managerEventStore,
});

const metrics = {
  sessionsCreatedTotal: 0,
  sessionsReusedTotal: 0,
  sessionsFailedTotal: 0,
  sessionsDestroyedTotal: 0,
  proxyHttpRequestsTotal: 0,
  proxyWsUpgradesTotal: 0,
  diagnosticsRequestsTotal: 0,
  launchDurationMsSum: 0,
  launchDurationMsCount: 0,
  lastReaperRunAt: 0,
};

async function bootstrap() {
  appCatalog = await loadCatalog(config.appCatalogPath, defaults);
  await restoreSessions();

  const server = http.createServer((request, response) => {
    handleRequest(request, response).catch((error) => {
      handleError(response, request, error);
    });
  });

  server.on("upgrade", (request, socket, head) => {
    handleUpgrade(request, socket, head).catch((error) => {
      log("error", "websocket_proxy_failed", {
        message: error.message,
        path: request.url,
      });

      const statusLine = error.statusCode === 401 ? "401 Unauthorized" : "502 Bad Gateway";
      socket.write(`HTTP/1.1 ${statusLine}\r\nConnection: close\r\n\r\n`);
      socket.destroy();
    });
  });

  server.on("clientError", (error, socket) => {
    log("warn", "client_error", { message: error.message });
    socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
  });

  server.listen(config.port, () => {
    log("info", "manager_listening", { port: config.port });
  });

  setInterval(() => {
    reapExpiredSessions().catch((error) => {
      log("error", "reaper_failed", { message: error.message });
    });
  }, config.reaperIntervalMs).unref();
}

async function handleRequest(request, response) {
  const url = new URL(request.url, "http://localhost");

  if (request.method === "GET" && url.pathname === "/healthz") {
    await runtimeClient.ping();
    return json(response, 200, {
      ok: true,
      sessions: sessions.size,
      catalogApps: appCatalog.size,
    });
  }

  if (request.method === "GET" && url.pathname === "/metrics") {
    response.writeHead(200, {
      "content-type": "text/plain; version=0.0.4; charset=utf-8",
      "cache-control": "no-store",
    });
    response.end(renderPrometheusMetrics());
    return;
  }

  if (request.method === "GET" && url.pathname === "/api/meta") {
    return json(response, 200, {
      adminRequired: Boolean(config.adminApiToken),
      allowCustomApps: config.allowCustomApps,
      publicBaseUrl: buildBaseUrl(request, config.publicBaseUrl),
      sessionBackend: config.sessionBackend,
      resumeSessions: config.resumeSessions,
      diagnosticsTail: config.sessionLogTail,
      metricsPath: "/metrics",
    });
  }

  if (request.method === "GET" && url.pathname === "/api/overview") {
    requireAdmin(request);
    return json(response, 200, buildOverview());
  }

  if (request.method === "GET" && url.pathname === "/api/apps") {
    return json(response, 200, {
      apps: [...appCatalog.values()].map(serializeCatalogApp),
    });
  }

  if (request.method === "GET" && url.pathname.startsWith("/app/")) {
    return handleDirectAppLaunch(request, response, url);
  }

  if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
    return serveStatic(response, "index.html", "text/html; charset=utf-8");
  }

  if (url.pathname.startsWith("/api/sessions")) {
    return handleSessionApi(request, response, url);
  }

  if (url.pathname.startsWith("/sessions/")) {
    return proxySessionHttp(request, response, url);
  }

  return text(response, 404, "Not found");
}

function requireAdmin(request, url = null) {
  if (!config.adminApiToken) {
    return;
  }

  const authorization = request.headers.authorization || "";
  const bearerToken = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
  const queryToken = url?.searchParams.get("adminToken") || "";
  const token = bearerToken || queryToken;
  if (token !== config.adminApiToken) {
    const error = new Error("Unauthorized");
    error.statusCode = 401;
    throw error;
  }
}

function getClientId(request, body = null, url = null) {
  const cookies = parseCookies(request.headers.cookie || "");
  return String(
    body?.clientId ||
      url?.searchParams.get("clientId") ||
      request.headers["x-appweb-client-id"] ||
      request.headers["x-client-id"] ||
      cookies.appweb_client_id ||
      ""
  ).trim();
}

function getOrCreateClientId(request, response, url = null) {
  const existingClientId = getClientId(request, null, url);
  if (existingClientId) {
    return existingClientId;
  }

  const generatedClientId = "client-" + createSessionId();
  appendSetCookie(
    response,
    serializeCookie("appweb_client_id", generatedClientId, {
      path: "/",
      maxAge: Math.floor(config.sessionTokenTtlMs / 1000),
      secure: config.secureCookies,
      sameSite: "Lax",
      httpOnly: false,
    })
  );

  return generatedClientId;
}

function appendSetCookie(response, cookieValue) {
  if (typeof response.setHeader !== "function") {
    return;
  }

  const existingCookies =
    typeof response.getHeader === "function" ? response.getHeader("set-cookie") : undefined;

  if (!existingCookies) {
    response.setHeader("set-cookie", cookieValue);
    return;
  }

  if (Array.isArray(existingCookies)) {
    response.setHeader("set-cookie", [...existingCookies, cookieValue]);
    return;
  }

  response.setHeader("set-cookie", [existingCookies, cookieValue]);
}

function resolveRequestedApp(body) {
  if (body.appId) {
    const app = appCatalog.get(String(body.appId));
    if (!app) {
      const error = new Error(`Unknown appId: ${body.appId}`);
      error.statusCode = 400;
      throw error;
    }
    return app;
  }

  if (!config.allowCustomApps || !body.app) {
    const error = new Error("Custom apps are disabled");
    error.statusCode = 400;
    throw error;
  }

  return normalizeApp(
    {
      id: body.app.id || `custom-${createSessionId()}`,
      ...body.app,
    },
    defaults
  );
}

async function handleSessionApi(request, response, url) {
  const diagnosticsMatch = url.pathname.match(/^\/api\/sessions\/([a-z0-9]+)\/diagnostics$/);
  if (request.method === "GET" && diagnosticsMatch) {
    requireAdmin(request);
    const session = sessions.get(diagnosticsMatch[1]);
    if (!session) {
      return json(response, 404, { error: "Session not found" });
    }

    metrics.diagnosticsRequestsTotal += 1;
    return json(response, 200, await buildSessionDiagnostics(session, url));
  }

  const sessionMatch = url.pathname.match(/^\/api\/sessions\/([a-z0-9]+)$/);
  if (sessionMatch) {
    const session = sessions.get(sessionMatch[1]);
    if (!session) {
      return json(response, 404, { error: "Session not found" });
    }

    if (request.method === "GET") {
      requireAdmin(request);
      await refreshSessionState(session);
      return json(response, 200, serializeSession(session, request));
    }

    if (request.method === "DELETE") {
      requireAdmin(request);
      await destroySession(session.id, "api_delete");
      return json(response, 200, { ok: true });
    }

    return text(response, 405, "Method not allowed");
  }

  if (request.method === "GET" && url.pathname === "/api/sessions") {
    requireAdmin(request);
    const requesterClientId = getClientId(request);
    const onlyMine = url.searchParams.get("mine") === "1";
    const filteredSessions = [...sessions.values()].filter((session) => {
      if (!onlyMine) {
        return true;
      }
      return requesterClientId && session.clientId === requesterClientId;
    });

    return json(response, 200, {
      sessions: filteredSessions.map((session) => serializeSession(session, request)),
    });
  }

  if (request.method === "POST" && url.pathname === "/api/sessions") {
    requireAdmin(request);
    const body = await readJsonBody(request);
    const app = resolveRequestedApp(body);
    const clientId = getClientId(request, body);
    const resumeIfExists = body.resumeIfExists !== false;
    const existingSession =
      resumeIfExists && app.session.resume && clientId
        ? findReusableSession(app.id, clientId)
        : null;

    if (existingSession) {
      markSessionReused(existingSession);
      return json(response, 200, serializeSession(existingSession, request, { reused: true }));
    }

    const session = await createSession(app, { clientId });
    return json(response, 201, serializeSession(session, request));
  }

  return text(response, 404, "Not found");
}

async function handleDirectAppLaunch(request, response, url) {
  const appMatch = url.pathname.match(/^\/app\/([a-z0-9][a-z0-9-_]*)\/?$/i);
  if (!appMatch) {
    return text(response, 404, "App not found");
  }

  requireAdmin(request, url);

  const appId = appMatch[1];
  const app = appCatalog.get(appId);
  if (!app) {
    return text(response, 404, "App not found");
  }

  const clientId = getOrCreateClientId(request, response, url);
  const resumeIfExists = url.searchParams.get("resume") !== "0";
  const existingSession =
    resumeIfExists && app.session.resume && clientId
      ? findReusableSession(app.id, clientId)
      : null;

  const session =
    existingSession ? markSessionReused(existingSession) : await createSession(app, { clientId });
  const serializedSession = serializeSession(
    session,
    request,
    existingSession ? { reused: true } : {}
  );

  response.writeHead(302, {
    location: serializedSession.url,
    "cache-control": "no-store",
  });
  response.end();
}

function findReusableSession(appId, clientId) {
  for (const session of sessions.values()) {
    if (session.appId !== appId || session.clientId !== clientId) {
      continue;
    }
    if (["ready", "starting"].includes(session.status)) {
      return session;
    }
  }

  return null;
}

function markSessionReused(session) {
  session.lastActivityAt = Date.now();
  session.reusedCount += 1;
  metrics.sessionsReusedTotal += 1;
  recordSessionEvent(session, "info", "session_reused", "Existing session reused", {
    reusedCount: session.reusedCount,
  });
  return session;
}

async function createSession(app, { clientId }) {
  const now = Date.now();
  const sessionId = createSessionId();
  const containerName = formatDockerName(config.containerPrefix, sessionId);
  const storage = resolveStorage(app, clientId);

  const session = {
    id: sessionId,
    appId: app.id,
    appName: app.name,
    clientId,
    containerId: "",
    containerName,
    runtimeHost: containerName,
    createdAt: now,
    lastActivityAt: now,
    sessionTtlMs: Number(app.sessionTtlMs || config.defaultSessionTtlMs),
    status: "starting",
    app,
    storage,
    events: [],
    reusedCount: 0,
    lastError: "",
    lastState: null,
    lastStats: null,
    timings: {
      createStartedAt: now,
      readyAt: 0,
      launchDurationMs: 0,
      readinessProbeCount: 0,
      lastProbeAt: 0,
    },
  };

  sessions.set(session.id, session);
  metrics.sessionsCreatedTotal += 1;
  recordSessionEvent(session, "info", "session_created", "Session record created", {
    storageMode: session.storage.mode,
    sourceType: app.source.type,
  });

  try {
    const created = await runtimeClient.createContainer(containerName, buildContainerSpec(session, app));
    session.containerId = created.Id;
    recordSessionEvent(session, "info", "container_created", "Session runtime object created", {
      containerId: session.containerId,
    });

    await runtimeClient.startContainer(session.containerId);
    recordSessionEvent(session, "info", "container_started", "Session runtime object started");

    await waitForSessionReady(session);
    session.status = "ready";
    session.timings.readyAt = Date.now();
    session.timings.launchDurationMs = session.timings.readyAt - session.timings.createStartedAt;
    metrics.launchDurationMsSum += session.timings.launchDurationMs;
    metrics.launchDurationMsCount += 1;
    recordSessionEvent(session, "info", "session_ready", "Session became ready", {
      launchDurationMs: session.timings.launchDurationMs,
      readinessProbeCount: session.timings.readinessProbeCount,
    });
  } catch (error) {
    metrics.sessionsFailedTotal += 1;
    session.lastError = error.message;
    recordSessionEvent(session, "error", "session_failed", "Session startup failed", {
      message: error.message,
    });

    try {
      if (session.containerId) {
        await destroySession(session.id, "startup_failure");
      } else {
        sessions.delete(session.id);
      }
    } catch (destroyError) {
      log("warn", "failed_to_cleanup_session", {
        sessionId: session.id,
        message: destroyError.message,
      });
      sessions.delete(session.id);
    }
    throw error;
  }

  return session;
}

function resolveStorage(app, clientId) {
  const mode = app.storage?.mode || defaults.storageMode;
  if (mode === "per-client") {
    if (!clientId) {
      return { mode: "ephemeral", homeVolumeName: "" };
    }
    return {
      mode,
      homeVolumeName: `${config.containerPrefix}-home-${slugify(clientId, "client")}-${app.id}`,
    };
  }

  if (mode === "shared-app") {
    return {
      mode,
      homeVolumeName: `${config.containerPrefix}-home-shared-${app.id}`,
    };
  }

  return { mode: "ephemeral", homeVolumeName: "" };
}

function buildContainerSpec(session, app) {
  const labels = {
    "appweb.managed": "true",
    "appweb.session-id": session.id,
    "appweb.app-id": app.id,
    "appweb.app-name": app.name,
    "appweb.client-id": session.clientId || "",
    "appweb.created-at": msToIso(session.createdAt),
    "appweb.storage-mode": session.storage.mode,
    "appweb.home-volume": session.storage.homeVolumeName || "",
    "appweb.source-type": app.source.type,
  };

  const env = [
    `PORT=${config.sessionInternalPort}`,
    `APP_SESSION_ID=${session.id}`,
    `APP_NAME=${app.name}`,
    `APP_SOURCE_TYPE=${app.source.type}`,
    `APP_SOURCE_URL=${app.source.url || ""}`,
    `APP_SOURCE_PATH=${app.source.path || ""}`,
    `APP_RUN_COMMAND=${app.source.command || ""}`,
    `APP_ARCHIVE_ENTRYPOINT=${app.source.archiveEntrypoint || ""}`,
    `APP_ARCHIVE_FORMAT=${app.source.archiveFormat || "auto"}`,
    `APP_ARCHIVE_STRIP_COMPONENTS=${app.source.archiveStripComponents || 0}`,
    `APP_ARGS=${app.launch.args || ""}`,
    `APP_SHA256=${app.source.sha256 || ""}`,
    `APPIMAGE_EXTRACT_AND_RUN=${app.launch.extractAndRun ? "1" : "0"}`,
    `APP_PRE_LAUNCH_COMMAND=${app.launch.preLaunchCommand || ""}`,
    `APP_WORKDIR=${app.launch.workingDirectory || ""}`,
    `SCREEN_WIDTH=${app.display.width}`,
    `SCREEN_HEIGHT=${app.display.height}`,
    `SCREEN_DEPTH=${app.display.depth}`,
    `APP_CACHE_DIR=/cache`,
    `SESSION_HOME=/data/home`,
  ];

  for (const [key, value] of Object.entries(app.env || {})) {
    env.push(`${key}=${value}`);
  }

  if (config.sessionBackend === "kubernetes") {
    return buildKubernetesPodSpec(session, app, labels, env);
  }

  return buildDockerContainerSpec(session, app, labels, env);
}

function buildDockerContainerSpec(session, app, labels, env) {
  const binds = [];
  if (config.cacheVolumeName) {
    binds.push(`${config.cacheVolumeName}:/cache`);
  }
  if (session.storage.homeVolumeName) {
    binds.push(`${session.storage.homeVolumeName}:/data/home`);
  }

  return {
    Image: config.sessionImage,
    WorkingDir: "/app",
    Env: env,
    Labels: labels,
    HostConfig: {
      AutoRemove: false,
      NetworkMode: config.sessionNetwork,
      ReadonlyRootfs: true,
      Memory: Math.max(128, Number(app.resources.memoryMb || config.defaultMemoryMb)) * 1024 * 1024,
      NanoCpus: Math.round(
        Math.max(0.1, Number(app.resources.cpuCores || config.defaultCpuCores)) * 1_000_000_000
      ),
      Binds: binds,
      Tmpfs: {
        "/tmp": "rw,nosuid,nodev,size=536870912",
        "/run": "rw,nosuid,nodev,size=67108864",
        "/data": "rw,nosuid,nodev,size=536870912",
      },
      CapAdd: ["CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE"],
      CapDrop: ["ALL"],
      SecurityOpt: ["no-new-privileges:true"],
    },
  };
}

function buildKubernetesPodSpec(session, app, labels, env) {
  const memoryLimit = `${Math.max(128, Number(app.resources.memoryMb || config.defaultMemoryMb))}Mi`;
  const cpuLimit = String(Math.max(0.1, Number(app.resources.cpuCores || config.defaultCpuCores)));
  const volumes = [
    { name: "tmp", emptyDir: {} },
    { name: "run", emptyDir: {} },
    { name: "data", emptyDir: {} },
  ];
  const volumeMounts = [
    { name: "tmp", mountPath: "/tmp" },
    { name: "run", mountPath: "/run" },
    { name: "data", mountPath: "/data" },
  ];

  if (config.k8sSessionCacheClaim) {
    volumes.push({
      name: "cache",
      persistentVolumeClaim: {
        claimName: config.k8sSessionCacheClaim,
      },
    });
    volumeMounts.push({
      name: "cache",
      mountPath: "/cache",
      subPath: `cache/${app.id}`,
    });
  } else {
    volumes.push({ name: "cache", emptyDir: {} });
    volumeMounts.push({ name: "cache", mountPath: "/cache" });
  }

  if (session.storage.homeVolumeName && config.k8sSessionHomeClaim) {
    volumes.push({
      name: "session-home",
      persistentVolumeClaim: {
        claimName: config.k8sSessionHomeClaim,
      },
    });
    volumeMounts.push({
      name: "session-home",
      mountPath: "/data/home",
      subPath: session.storage.homeVolumeName,
    });
  }

  return {
    apiVersion: "v1",
    kind: "Pod",
    metadata: {
      labels,
    },
    spec: {
      restartPolicy: "Never",
      automountServiceAccountToken: false,
      serviceAccountName: config.k8sSessionPodServiceAccount,
      containers: [
        {
          name: "session",
          image: config.sessionImage,
          imagePullPolicy: config.k8sSessionImagePullPolicy,
          env: env.map((value) => {
            const [name, ...rest] = value.split("=");
            return {
              name,
              value: rest.join("="),
            };
          }),
          ports: [
            {
              containerPort: config.sessionInternalPort,
              name: "http",
            },
          ],
          volumeMounts,
          resources: {
            requests: {
              cpu: cpuLimit,
              memory: memoryLimit,
            },
            limits: {
              cpu: cpuLimit,
              memory: memoryLimit,
            },
          },
          securityContext: {
            allowPrivilegeEscalation: false,
            readOnlyRootFilesystem: true,
            capabilities: {
              add: ["CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE"],
              drop: ["ALL"],
            },
          },
        },
      ],
      volumes,
    },
  };
}

async function waitForSessionReady(session) {
  const startedAt = Date.now();
  const probePath = session.app.launch?.healthcheckPath || "/";

  while (Date.now() - startedAt < config.sessionReadyTimeoutMs) {
    session.timings.readinessProbeCount += 1;
    session.timings.lastProbeAt = Date.now();

    const inspection = await runtimeClient.inspectContainer(session.containerId);
    syncSessionFromInspection(session, inspection);

    if (!inspection.State?.Running) {
      throw new Error(`Session container ${session.id} exited before becoming ready`);
    }

    try {
      const statusCode = await probeHttp(session.runtimeHost || session.containerName, config.sessionInternalPort, probePath);
      if (statusCode >= 200 && statusCode < 500) {
        return;
      }
    } catch {
      // Ignore probe failures until timeout.
    }

    await sleep(1000);
  }

  throw new Error(`Session ${session.id} did not become ready within ${config.sessionReadyTimeoutMs}ms`);
}

async function restoreSessions() {
  const containers = await runtimeClient.listContainers({
    label: ["appweb.managed=true"],
  });

  for (const container of containers) {
    const labels = container.Labels || {};
    const sessionId = labels["appweb.session-id"];
    if (!sessionId) {
      continue;
    }

    const now = Date.now();
    const sourceType = labels["appweb.source-type"] || "command";
    const session = {
      id: sessionId,
      appId: labels["appweb.app-id"] || "unknown",
      appName: labels["appweb.app-name"] || "Unknown App",
      clientId: labels["appweb.client-id"] || "",
      containerId: container.Id,
      containerName: (container.Names?.[0] || "").replace(/^\//, ""),
      runtimeHost: container.PodIP || (container.Names?.[0] || "").replace(/^\//, ""),
      createdAt: labels["appweb.created-at"] ? Date.parse(labels["appweb.created-at"]) : now,
      lastActivityAt: now,
      sessionTtlMs: config.defaultSessionTtlMs,
      status: container.State === "running" ? "ready" : container.State || "unknown",
      app: {
        id: labels["appweb.app-id"] || "unknown",
        name: labels["appweb.app-name"] || "Unknown App",
        description: "",
        icon: "",
        featured: false,
        categories: [],
        tags: [],
        source: {
          type: sourceType,
          command: "",
          url: "",
          sha256: "",
          path: "",
          archiveEntrypoint: "",
          archiveFormat: "auto",
          archiveStripComponents: 0,
        },
        launch: {
          args: "",
          extractAndRun: false,
          preLaunchCommand: "",
          workingDirectory: "",
          healthcheckPath: "/",
        },
        resources: { cpuCores: config.defaultCpuCores, memoryMb: config.defaultMemoryMb },
        display: {
          width: config.defaultScreenWidth,
          height: config.defaultScreenHeight,
          depth: config.defaultScreenDepth,
        },
        storage: {
          mode: labels["appweb.storage-mode"] || config.defaultStorageMode,
        },
        session: {
          resume: config.resumeSessions,
        },
        env: {},
        sessionTtlMs: config.defaultSessionTtlMs,
      },
      storage: {
        mode: labels["appweb.storage-mode"] || config.defaultStorageMode,
        homeVolumeName: labels["appweb.home-volume"] || "",
      },
      events: [],
      reusedCount: 0,
      lastError: "",
      lastState: null,
      lastStats: null,
      timings: {
        createStartedAt: labels["appweb.created-at"] ? Date.parse(labels["appweb.created-at"]) : now,
        readyAt: container.State === "running" ? now : 0,
        launchDurationMs: 0,
        readinessProbeCount: 0,
        lastProbeAt: 0,
      },
    };

    sessions.set(sessionId, session);
    recordSessionEvent(session, "info", "session_restored", "Session restored from runtime state", {
      status: session.status,
    });
  }
}

async function refreshSessionState(session) {
  try {
    const inspection = await runtimeClient.inspectContainer(session.containerId);
    syncSessionFromInspection(session, inspection);
  } catch (error) {
    if (error instanceof DockerError && error.statusCode === 404) {
      session.status = "deleted";
      session.lastError = "Container no longer exists";
      sessions.delete(session.id);
      return;
    }
    throw error;
  }
}

function syncSessionFromInspection(session, inspection) {
  const previousStatus = session.status;
  const state = inspection.State || {};
  session.runtimeHost =
    inspection.NetworkSettings?.IPAddress ||
    inspection.PodIP ||
    session.runtimeHost ||
    session.containerName;

  session.lastState = {
    running: Boolean(state.Running),
    status: state.Status || "unknown",
    exitCode: state.ExitCode,
    oomKilled: Boolean(state.OOMKilled),
    error: state.Error || "",
    startedAt: state.StartedAt || "",
    finishedAt: state.FinishedAt || "",
  };

  if (state.Running) {
    session.status = session.timings.readyAt ? "ready" : "starting";
  } else {
    session.status = state.Status || "stopped";
    session.lastError = state.Error || session.lastError || "";
  }

  if (previousStatus !== session.status) {
    recordSessionEvent(session, "info", "session_status_changed", "Session status changed", {
      from: previousStatus,
      to: session.status,
      exitCode: state.ExitCode,
    });
  }
}

async function destroySession(sessionId, reason = "manual") {
  const session = sessions.get(sessionId);
  if (!session) {
    return;
  }

  recordSessionEvent(session, "info", "session_destroying", "Destroying session", {
    reason,
  });

  try {
    await runtimeClient.stopContainer(session.containerId, 5);
  } catch (error) {
    const ignorable = error instanceof DockerError && [304, 404].includes(error.statusCode);
    if (!ignorable) {
      log("warn", "failed_to_stop_session", {
        sessionId,
        message: error.message,
      });
    }
  }

  try {
    await runtimeClient.removeContainer(session.containerId, true);
  } catch (error) {
    if (!(error instanceof DockerError) || error.statusCode !== 404) {
      throw error;
    }
  } finally {
    sessions.delete(sessionId);
    metrics.sessionsDestroyedTotal += 1;
  }
}

async function reapExpiredSessions() {
  metrics.lastReaperRunAt = Date.now();
  const now = Date.now();

  for (const session of [...sessions.values()]) {
    await refreshSessionState(session);

    const inactive = now > computeExpiry(session.lastActivityAt, session.sessionTtlMs);
    const stoppedTooLong =
      session.status !== "ready" && now - session.lastActivityAt > config.stoppedSessionGraceMs;

    if (inactive || stoppedTooLong) {
      await destroySession(session.id, inactive ? "session_ttl" : "stopped_grace");
    }
  }
}

function recordSessionEvent(session, level, event, message, details = {}) {
  const entry = {
    ts: new Date().toISOString(),
    level,
    event,
    message,
    ...details,
  };

  session.events.push(entry);
  if (session.events.length > config.maxSessionEvents) {
    session.events.splice(0, session.events.length - config.maxSessionEvents);
  }

  log(level, event, {
    sessionId: session.id,
    appId: session.appId,
    appName: session.appName,
    clientId: session.clientId,
    message,
    ...details,
  });
}

function serializeCatalogApp(app) {
  return {
    id: app.id,
    name: app.name,
    description: app.description,
    icon: app.icon,
    featured: app.featured,
    categories: app.categories,
    tags: app.tags,
    sourceType: app.source.type,
    resources: app.resources,
    display: app.display,
    storage: app.storage,
    session: app.session,
    launch: {
      healthcheckPath: app.launch.healthcheckPath,
      workingDirectory: app.launch.workingDirectory,
    },
  };
}

function serializeSession(session, request, extra = {}) {
  const baseUrl = buildBaseUrl(request, config.publicBaseUrl);
  const accessToken = signSessionToken(config.sessionSecret, session.id, config.sessionTokenTtlMs);
  const requesterClientId = getClientId(request);
  const launchDurationMs =
    session.timings.launchDurationMs ||
    (session.timings.readyAt ? session.timings.readyAt - session.timings.createStartedAt : 0);

  return {
    id: session.id,
    appId: session.appId,
    appName: session.appName,
    clientId: session.clientId,
    mine: Boolean(requesterClientId && requesterClientId === session.clientId),
    status: session.status,
    createdAt: msToIso(session.createdAt),
    lastActivityAt: msToIso(session.lastActivityAt),
    expiresAt: msToIso(computeExpiry(session.lastActivityAt, session.sessionTtlMs)),
    url: `${baseUrl}/sessions/${session.id}/?token=${encodeURIComponent(accessToken)}`,
    launchDurationMs,
    storage: session.storage,
    reusedCount: session.reusedCount,
    lastError: session.lastError,
    ...extra,
  };
}

async function buildSessionDiagnostics(session, url) {
  await refreshSessionState(session);

  let inspection = null;
  let logs = "";
  let stats = null;
  const tail = parseInteger(url.searchParams.get("tail"), config.sessionLogTail);

  try {
    inspection = await runtimeClient.inspectContainer(session.containerId);
  } catch (error) {
    if (!(error instanceof DockerError && error.statusCode === 404)) {
      throw error;
    }
  }

  try {
    logs = session.containerId
      ? await runtimeClient.getContainerLogs(session.containerId, { tail, timestamps: true })
      : "";
  } catch (error) {
    logs = `Unable to fetch container logs: ${error.message}`;
  }

  if (inspection?.State?.Running) {
    try {
      stats = formatContainerStats(await runtimeClient.getContainerStats(session.containerId));
      session.lastStats = stats;
    } catch {
      stats = session.lastStats;
    }
  }

  return {
    session: {
      id: session.id,
      appId: session.appId,
      appName: session.appName,
      clientId: session.clientId,
      status: session.status,
      storage: session.storage,
      createdAt: msToIso(session.createdAt),
      lastActivityAt: msToIso(session.lastActivityAt),
      sessionTtlMs: session.sessionTtlMs,
      launchDurationMs: session.timings.launchDurationMs,
      readinessProbeCount: session.timings.readinessProbeCount,
      lastError: session.lastError,
      reusedCount: session.reusedCount,
    },
    app: serializeCatalogApp(session.app),
    runtime: {
      inspect: inspection
        ? {
            state: inspection.State,
            hostConfig: inspection.HostConfig,
            mounts: inspection.Mounts,
            name: inspection.Name,
            config: inspection.Config,
          }
        : null,
      stats,
      events: session.events,
      logs,
    },
  };
}

function buildOverview() {
  const activeSessions = [...sessions.values()];
  const perApp = new Map();
  let configuredMemoryBytes = 0;
  let configuredCpuCores = 0;

  for (const session of activeSessions) {
    configuredMemoryBytes += Number(session.app.resources.memoryMb || 0) * 1024 * 1024;
    configuredCpuCores += Number(session.app.resources.cpuCores || 0);

    const current = perApp.get(session.appId) || {
      appId: session.appId,
      appName: session.appName,
      sourceType: session.app.source.type,
      activeSessions: 0,
      configuredMemoryMb: 0,
      configuredCpuCores: 0,
    };

    current.activeSessions += 1;
    current.configuredMemoryMb += Number(session.app.resources.memoryMb || 0);
    current.configuredCpuCores += Number(session.app.resources.cpuCores || 0);
    perApp.set(session.appId, current);
  }

  return {
    metrics: {
      ...metrics,
      activeSessions: activeSessions.length,
      configuredMemoryBytes,
      configuredCpuCores,
      averageLaunchDurationMs: metrics.launchDurationMsCount
        ? Math.round(metrics.launchDurationMsSum / metrics.launchDurationMsCount)
        : 0,
    },
    apps: [...perApp.values()].sort((left, right) => right.activeSessions - left.activeSessions),
    managerEvents: managerEventStore.list(60),
  };
}

function renderPrometheusMetrics() {
  const lines = [];
  const declared = new Set();
  const overview = buildOverview();

  pushMetric(lines, declared, "app_web_sessions_created_total", "counter", metrics.sessionsCreatedTotal, "Sessions created");
  pushMetric(lines, declared, "app_web_sessions_reused_total", "counter", metrics.sessionsReusedTotal, "Sessions reused");
  pushMetric(lines, declared, "app_web_sessions_failed_total", "counter", metrics.sessionsFailedTotal, "Sessions failed");
  pushMetric(lines, declared, "app_web_sessions_destroyed_total", "counter", metrics.sessionsDestroyedTotal, "Sessions destroyed");
  pushMetric(lines, declared, "app_web_proxy_http_requests_total", "counter", metrics.proxyHttpRequestsTotal, "HTTP requests proxied to sessions");
  pushMetric(lines, declared, "app_web_proxy_ws_upgrades_total", "counter", metrics.proxyWsUpgradesTotal, "WebSocket upgrades proxied to sessions");
  pushMetric(lines, declared, "app_web_diagnostics_requests_total", "counter", metrics.diagnosticsRequestsTotal, "Diagnostics requests");
  pushMetric(lines, declared, "app_web_sessions_active", "gauge", overview.metrics.activeSessions, "Active sessions");
  pushMetric(lines, declared, "app_web_session_launch_duration_ms_sum", "counter", metrics.launchDurationMsSum, "Sum of launch durations");
  pushMetric(lines, declared, "app_web_session_launch_duration_ms_count", "counter", metrics.launchDurationMsCount, "Count of launch durations");
  pushMetric(lines, declared, "app_web_configured_memory_bytes", "gauge", overview.metrics.configuredMemoryBytes, "Configured memory across active sessions");
  pushMetric(lines, declared, "app_web_configured_cpu_cores", "gauge", overview.metrics.configuredCpuCores, "Configured CPU across active sessions");
  pushMetric(lines, declared, "app_web_manager_last_reaper_run_timestamp", "gauge", Math.floor(metrics.lastReaperRunAt / 1000), "Timestamp of last reaper run");

  for (const appEntry of overview.apps) {
    pushMetric(lines, declared, "app_web_sessions_active_by_app", "gauge", appEntry.activeSessions, "Active sessions grouped by app", {
      app_id: appEntry.appId,
      app_name: appEntry.appName,
      source_type: appEntry.sourceType,
    });
    pushMetric(lines, declared, "app_web_configured_memory_mb_by_app", "gauge", appEntry.configuredMemoryMb, "Configured memory per app", {
      app_id: appEntry.appId,
      app_name: appEntry.appName,
    });
    pushMetric(lines, declared, "app_web_configured_cpu_cores_by_app", "gauge", appEntry.configuredCpuCores, "Configured CPU cores per app", {
      app_id: appEntry.appId,
      app_name: appEntry.appName,
    });
  }

  return `${lines.join("\n")}\n`;
}

function pushMetric(lines, declared, name, type, value, help, labels = null) {
  if (!declared.has(name) && help) {
    lines.push(`# HELP ${name} ${help}`);
    lines.push(`# TYPE ${name} ${type}`);
    declared.add(name);
  }
  lines.push(`${name}${formatMetricLabels(labels)} ${Number(value || 0)}`);
}

function formatMetricLabels(labels) {
  if (!labels || Object.keys(labels).length === 0) {
    return "";
  }

  const parts = Object.entries(labels).map(
    ([key, value]) => `${key}="${String(value).replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`
  );
  return `{${parts.join(",")}}`;
}

async function proxySessionHttp(request, response, url) {
  const route = resolveSessionRoute(url.pathname);
  if (!route) {
    return text(response, 404, "Session not found");
  }

  const session = sessions.get(route.sessionId);
  if (!session) {
    return text(response, 404, "Session not found");
  }

  await refreshSessionState(session);
  if (session.status !== "ready" && session.status !== "starting") {
    return text(response, 410, "Session is no longer running");
  }

  authorizeSessionRequest(request, response, session, url);
  session.lastActivityAt = Date.now();
  metrics.proxyHttpRequestsTotal += 1;

  const targetPath = buildTargetPath(route.innerPath, url.searchParams);
  const upstream = http.request(
    {
      hostname: session.runtimeHost || session.containerName,
      port: config.sessionInternalPort,
      path: targetPath,
      method: request.method,
      headers: {
        ...request.headers,
        host: `${session.runtimeHost || session.containerName}:${config.sessionInternalPort}`,
      },
    },
    (upstreamResponse) => {
      const headers = { ...upstreamResponse.headers };
      if (headers.location && headers.location.startsWith("/")) {
        headers.location = `/sessions/${session.id}${headers.location}`;
      }

      response.writeHead(upstreamResponse.statusCode || 502, headers);
      upstreamResponse.pipe(response);
    }
  );

  upstream.on("error", (error) => {
    log("error", "upstream_proxy_error", {
      sessionId: session.id,
      message: error.message,
    });

    if (!response.headersSent) {
      text(response, 502, "Upstream session is unavailable");
    } else {
      response.end();
    }
  });

  request.pipe(upstream);
}

async function handleUpgrade(request, socket, head) {
  const url = new URL(request.url, "http://localhost");
  const route = resolveSessionRoute(url.pathname);
  if (!route) {
    const error = new Error("Session not found");
    error.statusCode = 404;
    throw error;
  }

  const session = sessions.get(route.sessionId);
  if (!session) {
    const error = new Error("Session not found");
    error.statusCode = 404;
    throw error;
  }

  const fakeResponse = {
    setHeader() {},
  };
  authorizeSessionRequest(request, fakeResponse, session, url);
  session.lastActivityAt = Date.now();
  metrics.proxyWsUpgradesTotal += 1;

  const targetPath = buildTargetPath(route.innerPath, url.searchParams);
  const upstreamSocket = net.connect(config.sessionInternalPort, session.runtimeHost || session.containerName, () => {
    const headers = [];
    headers.push(`GET ${targetPath} HTTP/1.1`);

    for (const [headerName, headerValue] of Object.entries(request.headers)) {
      if (headerValue === undefined || headerName.toLowerCase() === "host") {
        continue;
      }

      headers.push(
        `${headerName}: ${Array.isArray(headerValue) ? headerValue.join(", ") : headerValue}`
      );
    }

    headers.push(`host: ${session.runtimeHost || session.containerName}:${config.sessionInternalPort}`);
    headers.push("");
    headers.push("");

    upstreamSocket.write(headers.join("\r\n"));
    if (head && head.length > 0) {
      upstreamSocket.write(head);
    }

    socket.pipe(upstreamSocket).pipe(socket);
  });

  upstreamSocket.on("error", (error) => {
    log("warn", "websocket_upstream_error", {
      sessionId: session.id,
      message: error.message,
    });
    socket.destroy();
  });
}

function resolveSessionRoute(pathname) {
  const match = pathname.match(/^\/sessions\/([a-z0-9]+)(\/.*)?$/);
  if (!match) {
    return null;
  }

  return {
    sessionId: match[1],
    innerPath: match[2] || "/",
  };
}

function buildTargetPath(innerPath, searchParams) {
  const forwarded = new URLSearchParams(searchParams);
  forwarded.delete("token");
  const query = forwarded.toString();
  return query ? `${innerPath}?${query}` : innerPath;
}

function authorizeSessionRequest(request, response, session, url) {
  const cookieName = `appweb_session_${session.id}`;
  const cookies = parseCookies(request.headers.cookie || "");
  const bearerHeader = request.headers.authorization || "";
  const bearerToken = bearerHeader.startsWith("Bearer ") ? bearerHeader.slice(7) : "";
  const queryToken = url.searchParams.get("token") || "";
  const cookieToken = cookies[cookieName] || "";
  const token = queryToken || cookieToken || bearerToken;

  if (!verifySessionToken(config.sessionSecret, token, session.id)) {
    const error = new Error("Unauthorized");
    error.statusCode = 401;
    throw error;
  }

  if (typeof response.setHeader === "function") {
    appendSetCookie(
      response,
      serializeCookie(cookieName, token, {
        path: `/sessions/${session.id}`,
        maxAge: Math.floor(config.sessionTokenTtlMs / 1000),
        secure: config.secureCookies,
        sameSite: "Strict",
      })
    );
  }
}

async function serveStatic(response, fileName, contentType) {
  const filePath = path.join(publicDir, fileName);
  const contents = await readFile(filePath);
  response.writeHead(200, {
    "content-type": contentType,
    "cache-control": "no-store",
  });
  response.end(contents);
}

async function probeHttp(hostname, port, targetPath) {
  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        hostname,
        port,
        path: targetPath,
        method: "GET",
      },
      (response) => {
        response.resume();
        resolve(response.statusCode || 0);
      }
    );

    request.setTimeout(3000, () => {
      request.destroy(new Error("Probe timeout"));
    });
    request.on("error", reject);
    request.end();
  });
}

function formatContainerStats(stats) {
  if (!stats) {
    return null;
  }

  if (stats.source === "kubernetes") {
    return {
      read: stats.timestamp || "",
      cpuPercent: 0,
      cpuNanoCores: stats.cpuNanoCores || 0,
      memoryBytes: stats.memoryBytes || 0,
      memoryLimitBytes: 0,
      memoryPercent: 0,
      networkRxBytes: 0,
      networkTxBytes: 0,
      source: "kubernetes",
    };
  }

  const cpuDelta =
    (stats.cpu_stats?.cpu_usage?.total_usage || 0) -
    (stats.precpu_stats?.cpu_usage?.total_usage || 0);
  const systemDelta =
    (stats.cpu_stats?.system_cpu_usage || 0) -
    (stats.precpu_stats?.system_cpu_usage || 0);
  const cpuCount =
    stats.cpu_stats?.online_cpus ||
    stats.cpu_stats?.cpu_usage?.percpu_usage?.length ||
    1;
  const cpuPercent =
    systemDelta > 0 ? Number(((cpuDelta / systemDelta) * cpuCount * 100).toFixed(2)) : 0;

  return {
    read: stats.read,
    cpuPercent,
    memoryBytes: stats.memory_stats?.usage || 0,
    memoryLimitBytes: stats.memory_stats?.limit || 0,
    memoryPercent:
      stats.memory_stats?.limit > 0
        ? Number(
            (((stats.memory_stats?.usage || 0) / stats.memory_stats.limit) * 100).toFixed(2)
          )
        : 0,
    networkRxBytes: Object.values(stats.networks || {}).reduce(
      (sum, network) => sum + (network.rx_bytes || 0),
      0
    ),
    networkTxBytes: Object.values(stats.networks || {}).reduce(
      (sum, network) => sum + (network.tx_bytes || 0),
      0
    ),
  };
}

function handleError(response, request, error) {
  const statusCode = error.statusCode || 500;
  log(statusCode >= 500 ? "error" : "warn", "request_failed", {
    path: request?.url || "",
    method: request?.method || "",
    statusCode,
    message: error.message || "Internal server error",
  });

  json(response, statusCode, {
    error: error.message || "Internal server error",
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

bootstrap().catch((error) => {
  log("error", "manager_start_failed", { message: error.message });
  process.exit(1);
});
