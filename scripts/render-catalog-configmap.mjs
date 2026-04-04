#!/usr/bin/env node

import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const sourcePath = path.join(repoRoot, "config", "apps.json");
const targetPath = path.join(repoRoot, "k8s", "configmap-catalog.yaml");

const rawCatalog = await readFile(sourcePath, "utf8");
const indentedCatalog = rawCatalog
  .trimEnd()
  .split(/\r?\n/)
  .map((line) => `    ${line}`)
  .join("\n");

const yaml = [
  "apiVersion: v1",
  "kind: ConfigMap",
  "metadata:",
  "  name: app-web-catalog",
  "  namespace: app-web",
  "data:",
  "  apps.json: |",
  indentedCatalog,
  "",
].join("\n");

await writeFile(targetPath, yaml, "utf8");
console.log(`Wrote ${targetPath}`);
