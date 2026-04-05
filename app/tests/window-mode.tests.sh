#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

assert_contains() {
  local haystack=$1
  local needle=$2
  local message=$3
  if [[ "${haystack}" != *"${needle}"* ]]; then
    printf 'ASSERTION FAILED: %s\nmissing: %s\n' "${message}" "${needle}" >&2
    exit 1
  fi
}

main() {
  export APP_ENTRYPOINT_LIBRARY_MODE=1
  export APP_USER="appuser"
  export APP_SESSION_ID="test-session"
  export SESSION_HOME="/tmp/window-mode-test-home"
  export XDG_RUNTIME_DIR="/tmp/window-mode-test-runtime"
  export LOG_DIR="/tmp/window-mode-test-logs"
  export DISPLAY=":100"
  export PORT="1234"
  export FILE_BRIDGE_PORT="9091"
  mkdir -p "${LOG_DIR}"

  # shellcheck source=../entrypoint.sh
  source "${ROOT_DIR}/entrypoint.sh"

  local electron_dir
  electron_dir="$(mktemp -d)"
  mkdir -p "${electron_dir}/resources"
  touch "${electron_dir}/resources/app.asar" "${electron_dir}/chrome-sandbox"
  looks_like_electron_artifact "${electron_dir}"

  export APP_WINDOW_MODE="auto"
  export APP_SOURCE_TYPE="command"
  export APP_RUN_COMMAND="VSCodium"
  export APP_ARGS="--disable-gpu"
  export APP_NAME="VSCodium"
  RESOLVED_COMMAND=""
  RESOLVED_WORKDIR=""
  RESOLVED_WINDOW_MODE=""

  resolve_launch_spec

  assert_contains "${RESOLVED_WINDOW_MODE}" "electron" "VSCodium should resolve to electron window mode"
  assert_contains "${RESOLVED_COMMAND}" "--kiosk" "Electron apps should receive kiosk flags"
  assert_contains "${RESOLVED_COMMAND}" "VSCodium" "resolved command should still launch the app"

  start_window_layout_agent
  local window_agent_script
  window_agent_script="$(cat /tmp/window-layout-agent.sh)"
  assert_contains "${window_agent_script}" "fullscreen" "Electron mode should force fullscreen window management"

  export APP_RUN_COMMAND="xterm"
  export APP_NAME="Terminal"
  export APP_ARGS=""
  RESOLVED_COMMAND=""
  RESOLVED_WORKDIR=""
  RESOLVED_WINDOW_MODE=""

  resolve_launch_spec

  assert_contains "${RESOLVED_WINDOW_MODE}" "immersive" "Non-Electron apps should use the fallback window mode"
  if [[ "${RESOLVED_COMMAND}" == *"--kiosk"* ]]; then
    echo "ASSERTION FAILED: fallback apps must not receive kiosk flags" >&2
    exit 1
  fi
}

main "$@"
