import http from "node:http";

export class DockerError extends Error {
  constructor(message, statusCode, payload) {
    super(message);
    this.name = "DockerError";
    this.statusCode = statusCode;
    this.payload = payload;
  }
}

export class DockerClient {
  constructor(socketPath) {
    this.socketPath = socketPath;
  }

  async ping() {
    return this.request("GET", "/_ping");
  }

  async listContainers(filters = {}) {
    const query = new URLSearchParams();
    query.set("all", "1");
    if (Object.keys(filters).length > 0) {
      query.set("filters", JSON.stringify(filters));
    }
    return this.request("GET", `/containers/json?${query.toString()}`);
  }

  async inspectContainer(containerId) {
    return this.request("GET", `/containers/${containerId}/json`);
  }

  async createContainer(name, body) {
    const query = new URLSearchParams({ name });
    return this.request("POST", `/containers/create?${query.toString()}`, body);
  }

  async startContainer(containerId) {
    return this.request("POST", `/containers/${containerId}/start`);
  }

  async stopContainer(containerId, timeoutSeconds = 10) {
    const query = new URLSearchParams({ t: String(timeoutSeconds) });
    return this.request("POST", `/containers/${containerId}/stop?${query.toString()}`);
  }

  async removeContainer(containerId, force = true) {
    const query = new URLSearchParams({ force: force ? "1" : "0" });
    return this.request("DELETE", `/containers/${containerId}?${query.toString()}`);
  }

  async getContainerLogs(containerId, options = {}) {
    const query = new URLSearchParams({
      stdout: options.stdout === false ? "0" : "1",
      stderr: options.stderr === false ? "0" : "1",
      tail: String(options.tail ?? 200),
      timestamps: options.timestamps === false ? "0" : "1",
    });

    const buffer = await this.requestBuffer("GET", `/containers/${containerId}/logs?${query.toString()}`);
    return demuxDockerLogStream(buffer);
  }

  async getContainerStats(containerId) {
    return this.request("GET", `/containers/${containerId}/stats?stream=0`);
  }

  request(method, requestPath, body) {
    return new Promise((resolve, reject) => {
      const payload = body ? JSON.stringify(body) : null;
      const request = http.request(
        {
          socketPath: this.socketPath,
          path: requestPath,
          method,
          headers: payload
            ? {
                "content-type": "application/json",
                "content-length": Buffer.byteLength(payload),
              }
            : undefined,
        },
        (response) => {
          const chunks = [];

          response.on("data", (chunk) => chunks.push(chunk));
          response.on("end", () => {
            const rawBody = Buffer.concat(chunks).toString("utf8");
            const parsedBody = rawBody ? safeParse(rawBody) : null;

            if ((response.statusCode || 500) >= 400) {
              reject(
                new DockerError(
                  parsedBody?.message || rawBody || `Docker API error ${response.statusCode}`,
                  response.statusCode || 500,
                  parsedBody ?? rawBody
                )
              );
              return;
            }

            resolve(parsedBody ?? rawBody);
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

  requestBuffer(method, requestPath) {
    return new Promise((resolve, reject) => {
      const request = http.request(
        {
          socketPath: this.socketPath,
          path: requestPath,
          method,
        },
        (response) => {
          const chunks = [];

          response.on("data", (chunk) => chunks.push(chunk));
          response.on("end", () => {
            const buffer = Buffer.concat(chunks);
            if ((response.statusCode || 500) >= 400) {
              const rawBody = buffer.toString("utf8");
              const parsedBody = rawBody ? safeParse(rawBody) : null;
              reject(
                new DockerError(
                  parsedBody?.message || rawBody || `Docker API error ${response.statusCode}`,
                  response.statusCode || 500,
                  parsedBody ?? rawBody
                )
              );
              return;
            }

            resolve(buffer);
          });
        }
      );

      request.on("error", reject);
      request.end();
    });
  }
}

function safeParse(value) {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function demuxDockerLogStream(buffer) {
  if (buffer.length < 8) {
    return buffer.toString("utf8");
  }

  let offset = 0;
  let output = "";
  let parsedFrames = 0;

  while (offset + 8 <= buffer.length) {
    const frameType = buffer[offset];
    const payloadLength = buffer.readUInt32BE(offset + 4);
    const frameStart = offset + 8;
    const frameEnd = frameStart + payloadLength;

    if (frameType < 1 || frameType > 3 || frameEnd > buffer.length) {
      if (parsedFrames === 0) {
        return buffer.toString("utf8");
      }
      break;
    }

    output += buffer.slice(frameStart, frameEnd).toString("utf8");
    offset = frameEnd;
    parsedFrames += 1;
  }

  return output;
}
