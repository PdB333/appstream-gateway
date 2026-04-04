import { slugify } from "./util.js";

export function resolveStorage(app, clientId, defaults, containerPrefix) {
  const mode = app.storage?.mode || defaults.storageMode;
  if (mode === "per-client") {
    if (!clientId) {
      return { mode: "ephemeral", homeVolumeName: "" };
    }
    return {
      mode,
      homeVolumeName: `${containerPrefix}-home-${slugify(clientId, "client")}-${app.id}`,
    };
  }

  if (mode === "shared-app") {
    return {
      mode,
      homeVolumeName: `${containerPrefix}-home-shared-${app.id}`,
    };
  }

  return { mode: "ephemeral", homeVolumeName: "" };
}
