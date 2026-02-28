import https from "node:https";
import { readFileSync } from "node:fs";

import { DockerError } from "./docker-api.js";

export class KubernetesClient {
  constructor(options = {}) {
    this.namespace =
      options.namespace ||
      process.env.K8S_NAMESPACE ||
      readFileOrEmpty("/var/run/secrets/kubernetes.io/serviceaccount/namespace") ||
      "default";
    this.apiServer =
      options.apiServer ||
      process.env.K8S_API_SERVER ||
      buildInClusterApiServer();
    this.token =
      options.token ||
      process.env.K8S_BEARER_TOKEN ||
      readFileOrEmpty("/var/run/secrets/kubernetes.io/serviceaccount/token");
    this.ca = options.ca || readFileOrNull("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt");
    this.agent = new https.Agent({
      keepAlive: true,
      ca: this.ca || undefined,
      rejectUnauthorized: true,
    });
  }

  async ping() {
    return this.request("GET", "/version");
  }

  async listContainers(filters = {}) {
    const labelFilters = Array.isArray(filters.label) ? filters.label : [];
    const query = new URLSearchParams();
    if (labelFilters.length > 0) {
      query.set("labelSelector", labelFilters.join(","));
    }

    const response = await this.request(
      "GET",
      `/api/v1/namespaces/${this.namespace}/pods?${query.toString()}`
    );

    return (response.items || []).map((pod) => normalizePodSummary(pod));
  }

  async createContainer(name, body) {
    const manifest = {
      metadata: {
        ...(body.metadata || {}),
        name,
        namespace: this.namespace,
      },
      ...body,
    };

    const response = await this.request("POST", `/api/v1/namespaces/${this.namespace}/pods`, manifest);
    return {
      Id: response.metadata.name,
    };
  }

  async startContainer(containerId) {
    return { Id: containerId };
  }

  async inspectContainer(containerId) {
    const pod = await this.request("GET", `/api/v1/namespaces/${this.namespace}/pods/${containerId}`);
    return normalizePodInspection(pod);
  }

  async stopContainer(containerId, timeoutSeconds = 10) {
    return this.request(
      "DELETE",
      `/api/v1/namespaces/${this.namespace}/pods/${containerId}`,
      {
        gracePeriodSeconds: timeoutSeconds,
      }
    );
  }

  async removeContainer(containerId) {
    try {
      return await this.request(
        "DELETE",
        `/api/v1/namespaces/${this.namespace}/pods/${containerId}`,
        {
          gracePeriodSeconds: 0,
        }
      );
    } catch (error) {
      if (error instanceof DockerError && [404, 409].includes(error.statusCode)) {
        return null;
      }
      throw error;
    }
  }

  async getContainerLogs(containerId, options = {}) {
    const query = new URLSearchParams({
      timestamps: options.timestamps === false ? "false" : "true",
      tailLines: String(options.tail ?? 200),
    });

    return this.requestText(
      "GET",
      `/api/v1/namespaces/${this.namespace}/pods/${containerId}/log?${query.toString()}`
    );
  }

  async getContainerStats(containerId) {
    try {
      const metrics = await this.request(
        "GET",
        `/apis/metrics.k8s.io/v1beta1/namespaces/${this.namespace}/pods/${containerId}`
      );

      const container = metrics.containers?.[0];
      if (!container) {
        return null;
      }

      return {
        source: "kubernetes",
        timestamp: metrics.timestamp,
        window: metrics.window,
        cpuNanoCores: parseCpuQuantity(container.usage?.cpu || "0"),
        memoryBytes: parseMemoryQuantity(container.usage?.memory || "0"),
      };
    } catch (error) {
      if (error instanceof DockerError && [404, 503].includes(error.statusCode)) {
        return null;
      }
      throw error;
    }
  }

  request(method, requestPath, body) {
    return this._request(method, requestPath, body, true);
  }

  requestText(method, requestPath, body) {
    return this._request(method, requestPath, body, false);
  }

  _request(method, requestPath, body, parseJson) {
    return new Promise((resolve, reject) => {
      const payload = body ? JSON.stringify(body) : null;
      const request = https.request(
        `${this.apiServer}${requestPath}`,
        {
          method,
          agent: this.agent,
          headers: {
            Authorization: `Bearer ${this.token}`,
            Accept: parseJson ? "application/json" : "text/plain",
            ...(payload
              ? {
                  "content-type": "application/json",
                  "content-length": Buffer.byteLength(payload),
                }
              : {}),
          },
        },
        (response) => {
          const chunks = [];
          response.on("data", (chunk) => chunks.push(chunk));
          response.on("end", () => {
            const rawBody = Buffer.concat(chunks).toString("utf8");
            const parsedBody = parseJson && rawBody ? safeParse(rawBody) : rawBody;

            if ((response.statusCode || 500) >= 400) {
              reject(
                new DockerError(
                  parsedBody?.message || rawBody || `Kubernetes API error ${response.statusCode}`,
                  response.statusCode || 500,
                  parsedBody
                )
              );
              return;
            }

            resolve(parsedBody);
          });
        }
      );

      request.on("error", reject);
      if (payload) {
        request.write(payload);
      }
      request.end();
    });
  }
}

function normalizePodSummary(pod) {
  return {
    Id: pod.metadata?.name,
    Names: [`/${pod.metadata?.name}`],
    Labels: pod.metadata?.labels || {},
    State: normalizePodStatus(pod).Status,
    PodIP: pod.status?.podIP || "",
  };
}

function normalizePodInspection(pod) {
  const normalizedStatus = normalizePodStatus(pod);
  const containerSpec = pod.spec?.containers?.[0] || {};
  return {
    Name: pod.metadata?.name || "",
    PodIP: pod.status?.podIP || "",
    NetworkSettings: {
      IPAddress: pod.status?.podIP || "",
    },
    State: normalizedStatus,
    Config: {
      Image: containerSpec.image || "",
      Env: containerSpec.env || [],
      Labels: pod.metadata?.labels || {},
    },
    HostConfig: {
      NodeName: pod.spec?.nodeName || "",
      ServiceAccountName: pod.spec?.serviceAccountName || "",
      RestartPolicy: pod.spec?.restartPolicy || "",
      Resources: containerSpec.resources || {},
      SecurityContext: containerSpec.securityContext || {},
    },
    Mounts: (containerSpec.volumeMounts || []).map((mount) => ({
      Name: mount.name,
      Destination: mount.mountPath,
      ReadOnly: Boolean(mount.readOnly),
      SubPath: mount.subPath || "",
    })),
    Pod: pod,
  };
}

function normalizePodStatus(pod) {
  const containerState = pod.status?.containerStatuses?.[0]?.state || {};
  const terminated = containerState.terminated || {};
  const waiting = containerState.waiting || {};
  const running = containerState.running || {};
  const phase = pod.status?.phase || "Unknown";

  return {
    Running: phase === "Running",
    Status: phase.toLowerCase(),
    ExitCode: terminated.exitCode,
    OOMKilled: terminated.reason === "OOMKilled",
    Error: waiting.message || terminated.message || "",
    StartedAt: running.startedAt || pod.status?.startTime || "",
    FinishedAt: terminated.finishedAt || "",
  };
}

function parseCpuQuantity(value) {
  const raw = String(value || "0").trim();
  const match = raw.match(/^([0-9.]+)(n|u|m)?$/);
  if (!match) {
    return 0;
  }

  const amount = Number.parseFloat(match[1]);
  const suffix = match[2] || "";
  const multipliers = {
    n: 1,
    u: 1_000,
    m: 1_000_000,
    "": 1_000_000_000,
  };

  return amount * (multipliers[suffix] || 1);
}

function parseMemoryQuantity(value) {
  const raw = String(value || "0").trim();
  const match = raw.match(/^([0-9.]+)(Ki|Mi|Gi|Ti|Pi|Ei|K|M|G|T|P|E)?$/);
  if (!match) {
    return 0;
  }

  const amount = Number.parseFloat(match[1]);
  const suffix = match[2] || "";
  const multipliers = {
    "": 1,
    Ki: 1024,
    Mi: 1024 ** 2,
    Gi: 1024 ** 3,
    Ti: 1024 ** 4,
    Pi: 1024 ** 5,
    Ei: 1024 ** 6,
    K: 1000,
    M: 1000 ** 2,
    G: 1000 ** 3,
    T: 1000 ** 4,
    P: 1000 ** 5,
    E: 1000 ** 6,
  };

  return amount * (multipliers[suffix] || 1);
}

function buildInClusterApiServer() {
  const host = process.env.KUBERNETES_SERVICE_HOST;
  const port = process.env.KUBERNETES_SERVICE_PORT_HTTPS || process.env.KUBERNETES_SERVICE_PORT || "443";
  return `https://${host}:${port}`;
}

function safeParse(value) {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function readFileOrEmpty(filePath) {
  try {
    return readFileSync(filePath, "utf8").trim();
  } catch {
    return "";
  }
}

function readFileOrNull(filePath) {
  try {
    return readFileSync(filePath);
  } catch {
    return null;
  }
}
