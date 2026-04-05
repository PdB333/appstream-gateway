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
  export APP_SOURCE_TYPE=command
  export APP_RUN_COMMAND="xterm"
  export APP_USER="appuser"
  export APP_SESSION_ID="test-session"
  export SESSION_HOME="/tmp/xpra-test-home"
  export XDG_RUNTIME_DIR="/tmp/xpra-test-runtime"
  export DISPLAY=":100"
  export PORT="1234"
  export FILE_BRIDGE_PORT="9091"

  # shellcheck source=../entrypoint.sh
  source "${ROOT_DIR}/entrypoint.sh"

  build_xpra_args

  local joined="${XPRA_ARGS[*]}"
  assert_contains "${joined}" "start" "xpra command should start the server"
  assert_contains "${joined}" ":100" "xpra command should use the configured display"
  assert_contains "${joined}" "--bind-tcp=0.0.0.0:1234" "xpra command should bind the session HTTP port"
  assert_contains "${joined}" "--html=on" "xpra command should expose the HTML5 client"
  assert_contains "${joined}" "--dpi=96" "xpra command should force the configured DPI"
  assert_contains "${joined}" "--resize-display=yes" "xpra command should resize to the client viewport"
  assert_contains "${joined}" "--start-child=dbus-run-session -- /bin/bash /tmp/start-app.sh" "xpra command should launch the app child"

  write_app_script
  local app_script
  app_script="$(cat /tmp/start-app.sh)"
  assert_contains "${app_script}" "XDG_CURRENT_DESKTOP=\"Xpra\"" "app script should identify the Xpra session"
  assert_contains "${app_script}" "XAUTHORITY=\"${SESSION_HOME}/.Xauthority\"" "app script should use the session Xauthority"
  assert_contains "${app_script}" "APP_LAUNCH_COMMAND" "app script should embed the resolved launch command"
}

main "$@"
