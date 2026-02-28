import { readFile } from "node:fs/promises";

export async function loadCatalog(catalogPath, defaults) {
  const fileContents = await readFile(catalogPath, "utf8");
  const rawCatalog = JSON.parse(fileContents);

  if (!Array.isArray(rawCatalog)) {
    throw new Error("Application catalog must be a JSON array");
  }

  const apps = rawCatalog.map((entry) => normalizeApp(entry, defaults));
  return new Map(apps.map((app) => [app.id, app]));
}

export function normalizeApp(rawApp, defaults) {
  if (!rawApp || typeof rawApp !== "object") {
    throw new Error("Invalid application definition");
  }

  const source = rawApp.source || {};
  if (!rawApp.id || !/^[a-z0-9-]+$/.test(rawApp.id)) {
    throw new Error(`Invalid app id: ${rawApp.id}`);
  }
  if (!rawApp.name) {
    throw new Error(`App ${rawApp.id} is missing a name`);
  }
  if (!["command", "appimage-url", "appimage-file", "binary-path", "archive-url"].includes(source.type)) {
    throw new Error(`App ${rawApp.id} has unsupported source type: ${source.type}`);
  }
  if (source.type === "command" && !source.command) {
    throw new Error(`App ${rawApp.id} requires source.command`);
  }
  if (source.type === "appimage-url" && !source.url) {
    throw new Error(`App ${rawApp.id} requires source.url`);
  }
  if ((source.type === "appimage-file" || source.type === "binary-path") && !source.path) {
    throw new Error(`App ${rawApp.id} requires source.path`);
  }
  if (source.type === "archive-url" && (!source.url || !source.archiveEntrypoint)) {
    throw new Error(`App ${rawApp.id} requires source.url and source.archiveEntrypoint`);
  }
  if (source.archiveFormat && !["auto", "zip", "tar"].includes(String(source.archiveFormat))) {
    throw new Error(`App ${rawApp.id} has unsupported archiveFormat: ${source.archiveFormat}`);
  }

  return {
    id: rawApp.id,
    name: String(rawApp.name),
    description: rawApp.description ? String(rawApp.description) : "",
    icon: rawApp.icon ? String(rawApp.icon) : "",
    featured: Boolean(rawApp.featured),
    categories: normalizeStringArray(rawApp.categories, "categories"),
    tags: normalizeStringArray(rawApp.tags, "tags"),
    source: {
      type: source.type,
      command: source.command ? String(source.command) : "",
      url: source.url ? String(source.url) : "",
      sha256: source.sha256 ? String(source.sha256) : "",
      path: source.path ? String(source.path) : "",
      archiveEntrypoint: source.archiveEntrypoint ? String(source.archiveEntrypoint) : "",
      archiveFormat: source.archiveFormat ? String(source.archiveFormat) : "auto",
      archiveStripComponents: Number(source.archiveStripComponents ?? 0),
    },
    launch: {
      args: rawApp.launch?.args ? String(rawApp.launch.args) : "",
      extractAndRun:
        rawApp.launch?.extractAndRun === undefined
          ? source.type === "appimage-url"
          : Boolean(rawApp.launch.extractAndRun),
      preLaunchCommand: rawApp.launch?.preLaunchCommand
        ? String(rawApp.launch.preLaunchCommand)
        : "",
      workingDirectory: rawApp.launch?.workingDirectory
        ? String(rawApp.launch.workingDirectory)
        : "",
      healthcheckPath: rawApp.launch?.healthcheckPath
        ? String(rawApp.launch.healthcheckPath)
        : "/",
    },
    resources: {
      cpuCores: Number(rawApp.resources?.cpuCores ?? defaults.cpuCores),
      memoryMb: Number(rawApp.resources?.memoryMb ?? defaults.memoryMb),
    },
    display: {
      width: Number(rawApp.display?.width ?? defaults.width),
      height: Number(rawApp.display?.height ?? defaults.height),
      depth: Number(rawApp.display?.depth ?? defaults.depth),
    },
    storage: {
      mode: normalizeStorageMode(rawApp.storage?.mode ?? defaults.storageMode),
    },
    session: {
      resume:
        rawApp.session?.resume === undefined
          ? defaults.resumeSessions
          : Boolean(rawApp.session.resume),
    },
    env: normalizeEnv(rawApp.env),
    sessionTtlMs: rawApp.sessionTtlMs ? Number(rawApp.sessionTtlMs) : defaults.sessionTtlMs,
  };
}

function normalizeEnv(rawEnv) {
  if (!rawEnv) {
    return {};
  }

  const output = {};
  for (const [key, value] of Object.entries(rawEnv)) {
    if (!/^[A-Z0-9_]+$/i.test(key)) {
      throw new Error(`Invalid environment variable name: ${key}`);
    }
    output[key] = String(value);
  }

  return output;
}

function normalizeStringArray(rawValue, fieldName) {
  if (!rawValue) {
    return [];
  }

  if (!Array.isArray(rawValue)) {
    throw new Error(`${fieldName} must be an array`);
  }

  return rawValue.map((value) => String(value)).filter(Boolean);
}

function normalizeStorageMode(mode) {
  const normalized = String(mode || "ephemeral");
  if (!["ephemeral", "per-client", "shared-app"].includes(normalized)) {
    throw new Error(`Unsupported storage mode: ${mode}`);
  }

  return normalized;
}
