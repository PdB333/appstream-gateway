#!/usr/bin/env bash
set -euo pipefail

APP_SESSION_ID="${APP_SESSION_ID:-unknown}"
APP_USER="${APP_USER:-appuser}"
APP_NAME="${APP_NAME:-Remote App}"
APP_SOURCE_TYPE="${APP_SOURCE_TYPE:-command}"
APP_SOURCE_URL="${APP_SOURCE_URL:-}"
APP_SOURCE_PATH="${APP_SOURCE_PATH:-}"
APP_RUN_COMMAND="${APP_RUN_COMMAND:-}"
APP_ARCHIVE_ENTRYPOINT="${APP_ARCHIVE_ENTRYPOINT:-}"
APP_ARCHIVE_FORMAT="${APP_ARCHIVE_FORMAT:-auto}"
APP_ARCHIVE_STRIP_COMPONENTS="${APP_ARCHIVE_STRIP_COMPONENTS:-0}"
APP_ARGS="${APP_ARGS:-}"
APP_SHA256="${APP_SHA256:-}"
APPIMAGE_EXTRACT_AND_RUN="${APPIMAGE_EXTRACT_AND_RUN:-1}"
APP_PRE_LAUNCH_COMMAND="${APP_PRE_LAUNCH_COMMAND:-}"
APP_WORKDIR="${APP_WORKDIR:-}"
APP_CACHE_DIR="${APP_CACHE_DIR:-/cache}"
APP_DOWNLOAD_DIR="${APP_DOWNLOAD_DIR:-/data/downloads}"
DATA_DIR="${DATA_DIR:-/data}"
SESSION_HOME="${SESSION_HOME:-/data/home}"
DISPLAY="${DISPLAY:-:0}"
PORT="${PORT:-8080}"
VNC_PORT="${VNC_PORT:-5900}"
SCREEN_WIDTH="${SCREEN_WIDTH:-1440}"
SCREEN_HEIGHT="${SCREEN_HEIGHT:-900}"
SCREEN_DEPTH="${SCREEN_DEPTH:-24}"
NOVNC_WEB_ROOT="${NOVNC_WEB_ROOT:-/app/public}"
XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/tmp/runtime-${APP_USER}}"
LOG_DIR="${LOG_DIR:-/tmp/app-web-logs}"
APP_WINDOW_MODE="${APP_WINDOW_MODE:-immersive}"
X11VNC_NCACHE="${X11VNC_NCACHE:-10}"
X11VNC_NOXDAMAGE="${X11VNC_NOXDAMAGE:-1}"

declare -a pids=()
app_pid=""
RESOLVED_COMMAND=""
RESOLVED_WORKDIR=""

json_escape() {
  local value=${1-}
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  value=${value//$'\n'/\\n}
  value=${value//$'\r'/\\r}
  value=${value//$'\t'/\\t}
  printf '%s' "${value}"
}

emit_log() {
  local level=$1
  local event=$2
  local message=$3
  local component=${4:-runtime}

  printf '{"ts":"%s","level":"%s","component":"%s","event":"%s","sessionId":"%s","appName":"%s","message":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "$(json_escape "${level}")" \
    "$(json_escape "${component}")" \
    "$(json_escape "${event}")" \
    "$(json_escape "${APP_SESSION_ID}")" \
    "$(json_escape "${APP_NAME}")" \
    "$(json_escape "${message}")" >&2
}

is_enabled() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

cleanup() {
  local exit_code=$?

  emit_log "info" "session_stopping" "Stopping session"
  if [[ -n "${app_pid}" ]]; then
    kill "${app_pid}" 2>/dev/null || true
  fi

  for pid in "${pids[@]:-}"; do
    kill "${pid}" 2>/dev/null || true
  done

  wait || true
  exit "${exit_code}"
}

trap cleanup EXIT INT TERM

ensure_user() {
  if ! id "${APP_USER}" >/dev/null 2>&1; then
    useradd --create-home --shell /bin/bash "${APP_USER}"
  fi
}

prepare_directories() {
  mkdir -p \
    "${APP_CACHE_DIR}" \
    "${APP_DOWNLOAD_DIR}" \
    "${SESSION_HOME}" \
    "${SESSION_HOME}/.config" \
    "${SESSION_HOME}/.cache" \
    "${SESSION_HOME}/.local/share" \
    "${XDG_RUNTIME_DIR}" \
    "${LOG_DIR}" \
    /tmp \
    /tmp/.X11-unix
  touch "${LOG_DIR}/xvfb.log" "${LOG_DIR}/openbox.log" "${LOG_DIR}/x11vnc.log" "${LOG_DIR}/websockify.log" "${LOG_DIR}/window-agent.log" "${LOG_DIR}/app.log"
  chmod 1777 /tmp /tmp/.X11-unix
  chmod 0700 "${XDG_RUNTIME_DIR}"
  chown -R "${APP_USER}:${APP_USER}" "${APP_CACHE_DIR}" "${DATA_DIR}" "${XDG_RUNTIME_DIR}" "${SESSION_HOME}"
}

tail_component_log() {
  local component=$1
  local file_path=$2

  (
    tail -n +1 -F "${file_path}" 2>/dev/null | while IFS= read -r line; do
      emit_log "info" "${component}_output" "${line}" "${component}"
    done
  ) &
  pids+=("$!")
}

start_log_forwarders() {
  tail_component_log "xvfb" "${LOG_DIR}/xvfb.log"
  tail_component_log "openbox" "${LOG_DIR}/openbox.log"
  tail_component_log "x11vnc" "${LOG_DIR}/x11vnc.log"
  tail_component_log "websockify" "${LOG_DIR}/websockify.log"
  tail_component_log "window_agent" "${LOG_DIR}/window-agent.log"
  tail_component_log "app" "${LOG_DIR}/app.log"
}

wait_for_display() {
  local retries=60

  until runuser -u "${APP_USER}" -- env DISPLAY="${DISPLAY}" xdpyinfo >/dev/null 2>&1; do
    retries=$((retries - 1))
    if (( retries == 0 )); then
      emit_log "error" "display_not_ready" "Display did not become ready"
      return 1
    fi
    sleep 0.5
  done
}

wait_for_port() {
  local host=$1
  local port=$2
  local retries=${3:-60}

  until bash -c ">/dev/tcp/${host}/${port}" >/dev/null 2>&1; do
    retries=$((retries - 1))
    if (( retries == 0 )); then
      emit_log "error" "port_not_ready" "Port ${host}:${port} did not become ready"
      return 1
    fi
    sleep 0.5
  done
}

download_artifact() {
  local url=$1
  local sha256_value=$2
  local suffix=$3
  local file_name cache_key target_path

  file_name="$(basename "${url%%\?*}")"
  if [[ -z "${file_name}" ]]; then
    file_name="${APP_NAME// /-}${suffix}"
  fi

  cache_key="$(printf '%s' "${url}" | sha256sum | awk '{print $1}')"
  target_path="${APP_CACHE_DIR}/${cache_key}-${file_name}"

  if [[ ! -f "${target_path}" ]]; then
    emit_log "info" "artifact_download_start" "Downloading ${url}"
    curl --fail --silent --show-error --location "${url}" --output "${target_path}.tmp"
    if [[ -n "${sha256_value}" ]]; then
      printf '%s  %s\n' "${sha256_value}" "${target_path}.tmp" | sha256sum --check --status
    fi
    mv "${target_path}.tmp" "${target_path}"
  fi

  printf '%s' "${target_path}"
}

prepare_appimage() {
  local appimage_path=$1
  local staged_path

  staged_path="${APP_DOWNLOAD_DIR}/$(basename "${appimage_path}")"
  cp -f "${appimage_path}" "${staged_path}"
  chmod 0755 "${staged_path}"
  chown "${APP_USER}:${APP_USER}" "${staged_path}" 2>/dev/null || true
  printf '%s' "${staged_path}"
}

prepare_archive() {
  local archive_path=$1
  local cache_key extract_dir

  cache_key="$(printf '%s' "${archive_path}:${APP_ARCHIVE_ENTRYPOINT}:${APP_ARCHIVE_STRIP_COMPONENTS}" | sha256sum | awk '{print $1}')"
  extract_dir="${APP_CACHE_DIR}/extract-${cache_key}"

  if [[ ! -d "${extract_dir}" ]]; then
    mkdir -p "${extract_dir}"
    emit_log "info" "archive_extract_start" "Extracting archive ${archive_path}"

    case "${APP_ARCHIVE_FORMAT}" in
      auto)
        if [[ "${archive_path}" == *.zip ]]; then
          unzip -q -o "${archive_path}" -d "${extract_dir}"
        else
          tar -xf "${archive_path}" -C "${extract_dir}" --strip-components="${APP_ARCHIVE_STRIP_COMPONENTS}"
        fi
        ;;
      zip)
        unzip -q -o "${archive_path}" -d "${extract_dir}"
        ;;
      tar)
        tar -xf "${archive_path}" -C "${extract_dir}" --strip-components="${APP_ARCHIVE_STRIP_COMPONENTS}"
        ;;
      *)
        emit_log "error" "archive_format_invalid" "Unsupported archive format ${APP_ARCHIVE_FORMAT}"
        return 1
        ;;
    esac
  fi

  printf '%s' "${extract_dir}"
}

resolve_launch_spec() {
  local artifact_path archive_dir quoted_path

  RESOLVED_WORKDIR="${APP_WORKDIR}"

  case "${APP_SOURCE_TYPE}" in
    command)
      if [[ -z "${APP_RUN_COMMAND}" ]]; then
        emit_log "error" "launch_spec_invalid" "APP_RUN_COMMAND is required for command sources"
        return 1
      fi
      RESOLVED_COMMAND="${APP_RUN_COMMAND} ${APP_ARGS}"
      ;;
    binary-path)
      if [[ -z "${APP_SOURCE_PATH}" ]]; then
        emit_log "error" "launch_spec_invalid" "APP_SOURCE_PATH is required for binary-path sources"
        return 1
      fi
      printf -v quoted_path '%q' "${APP_SOURCE_PATH}"
      RESOLVED_COMMAND="${quoted_path} ${APP_ARGS}"
      ;;
    appimage-file)
      if [[ -z "${APP_SOURCE_PATH}" ]]; then
        emit_log "error" "launch_spec_invalid" "APP_SOURCE_PATH is required for appimage-file sources"
        return 1
      fi
      artifact_path="$(prepare_appimage "${APP_SOURCE_PATH}")"
      printf -v quoted_path '%q' "${artifact_path}"
      if [[ "${APPIMAGE_EXTRACT_AND_RUN}" == "1" ]]; then
        RESOLVED_COMMAND="${quoted_path} --appimage-extract-and-run ${APP_ARGS}"
      else
        RESOLVED_COMMAND="${quoted_path} ${APP_ARGS}"
      fi
      ;;
    appimage-url)
      if [[ -z "${APP_SOURCE_URL}" ]]; then
        emit_log "error" "launch_spec_invalid" "APP_SOURCE_URL is required for appimage-url sources"
        return 1
      fi
      artifact_path="$(download_artifact "${APP_SOURCE_URL}" "${APP_SHA256}" ".AppImage")"
      artifact_path="$(prepare_appimage "${artifact_path}")"
      printf -v quoted_path '%q' "${artifact_path}"
      if [[ "${APPIMAGE_EXTRACT_AND_RUN}" == "1" ]]; then
        RESOLVED_COMMAND="${quoted_path} --appimage-extract-and-run ${APP_ARGS}"
      else
        RESOLVED_COMMAND="${quoted_path} ${APP_ARGS}"
      fi
      ;;
    archive-url)
      if [[ -z "${APP_SOURCE_URL}" || -z "${APP_ARCHIVE_ENTRYPOINT}" ]]; then
        emit_log "error" "launch_spec_invalid" "APP_SOURCE_URL and APP_ARCHIVE_ENTRYPOINT are required for archive-url sources"
        return 1
      fi
      artifact_path="$(download_artifact "${APP_SOURCE_URL}" "${APP_SHA256}" ".archive")"
      archive_dir="$(prepare_archive "${artifact_path}")"
      if [[ -z "${RESOLVED_WORKDIR}" ]]; then
        RESOLVED_WORKDIR="${archive_dir}"
      fi
      printf -v quoted_path '%q' "${archive_dir}/${APP_ARCHIVE_ENTRYPOINT}"
      RESOLVED_COMMAND="${quoted_path} ${APP_ARGS}"
      ;;
    *)
      emit_log "error" "launch_spec_invalid" "Unsupported source type ${APP_SOURCE_TYPE}"
      return 1
      ;;
  esac
}

write_app_script() {
  resolve_launch_spec

  cat > /tmp/start-app.sh <<EOF
#!/usr/bin/env bash
set -euo pipefail
export HOME="${SESSION_HOME}"
export USER="${APP_USER}"
export LOGNAME="${APP_USER}"
export DISPLAY="${DISPLAY}"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR}"
export XDG_CONFIG_HOME="${SESSION_HOME}/.config"
export XDG_CACHE_HOME="${SESSION_HOME}/.cache"
export XDG_DATA_HOME="${SESSION_HOME}/.local/share"
export DESKTOP_SESSION="openbox"
export NO_AT_BRIDGE=1
mkdir -p "\${XDG_CONFIG_HOME}" "\${XDG_CACHE_HOME}" "\${XDG_DATA_HOME}" "\${HOME}"
EOF

  if [[ -n "${RESOLVED_WORKDIR}" ]]; then
    printf 'cd -- %q\n' "${RESOLVED_WORKDIR}" >> /tmp/start-app.sh
  fi
  if [[ -n "${APP_PRE_LAUNCH_COMMAND}" ]]; then
    printf 'APP_PRE_LAUNCH_COMMAND=%q\n' "${APP_PRE_LAUNCH_COMMAND}" >> /tmp/start-app.sh
    printf '/bin/bash -lc "$APP_PRE_LAUNCH_COMMAND"\n' >> /tmp/start-app.sh
  fi
  printf 'APP_LAUNCH_COMMAND=%q\n' "${RESOLVED_COMMAND}" >> /tmp/start-app.sh
  printf 'exec /bin/bash -lc "$APP_LAUNCH_COMMAND"\n' >> /tmp/start-app.sh

  chmod 0755 /tmp/start-app.sh
}

start_xvfb() {
  emit_log "info" "xvfb_start" "Starting Xvfb"
  runuser -u "${APP_USER}" -- env DISPLAY="${DISPLAY}" Xvfb "${DISPLAY}" -screen 0 "${SCREEN_WIDTH}x${SCREEN_HEIGHT}x${SCREEN_DEPTH}" -ac -nolisten tcp >>"${LOG_DIR}/xvfb.log" 2>&1 &
  pids+=("$!")
}

start_window_manager() {
  emit_log "info" "openbox_start" "Starting openbox"
  runuser -u "${APP_USER}" -- env \
    DISPLAY="${DISPLAY}" \
    HOME="${SESSION_HOME}" \
    XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR}" \
    XDG_CONFIG_HOME="${SESSION_HOME}/.config" \
    XDG_CACHE_HOME="${SESSION_HOME}/.cache" \
    XDG_DATA_HOME="${SESSION_HOME}/.local/share" \
    openbox --sm-disable >>"${LOG_DIR}/openbox.log" 2>&1 &
  pids+=("$!")
}

set_root_background() {
  runuser -u "${APP_USER}" -- env DISPLAY="${DISPLAY}" HOME="${SESSION_HOME}" XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR}" xsetroot -solid "#050505" >>"${LOG_DIR}/window-agent.log" 2>&1 || true
}

start_window_layout_agent() {
  if [[ "${APP_WINDOW_MODE}" != "immersive" ]]; then
    return
  fi

  emit_log "info" "window_agent_start" "Starting immersive window layout agent"

  cat > /tmp/window-layout-agent.sh <<EOF
#!/usr/bin/env bash
set -euo pipefail
export DISPLAY="${DISPLAY}"
export HOME="${SESSION_HOME}"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR}"
screen_width="${SCREEN_WIDTH}"
screen_height="${SCREEN_HEIGHT}"

while true; do
  while read -r window_id desktop host window_class rest; do
    [[ -z "\${window_id}" ]] && continue
    case "\${window_class}" in
      *Openbox*|*openbox*|*Desktop*|*desktop_window*) continue ;;
    esac
    wmctrl -i -r "\${window_id}" -b add,maximized_vert,maximized_horz,fullscreen >/dev/null 2>&1 || true
    wmctrl -i -r "\${window_id}" -e "0,0,0,\${screen_width},\${screen_height}" >/dev/null 2>&1 || true
    wmctrl -i -a "\${window_id}" >/dev/null 2>&1 || true
  done < <(wmctrl -lx 2>/dev/null)
  sleep 1
done
EOF

  chmod 0755 /tmp/window-layout-agent.sh
  runuser -u "${APP_USER}" -- env DISPLAY="${DISPLAY}" HOME="${SESSION_HOME}" XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR}" /tmp/window-layout-agent.sh >>"${LOG_DIR}/window-agent.log" 2>&1 &
  pids+=("$!")
}

start_x11vnc() {
  local -a x11vnc_args=(
    -display "${DISPLAY}"
    -shared
    -forever
    -localhost
    -nopw
    -rfbport "${VNC_PORT}"
    -xkb
    -repeat
    -wait 10
    -defer 10
  )

  if is_enabled "${X11VNC_NOXDAMAGE}"; then
    x11vnc_args+=(-noxdamage)
  fi

  if [[ "${X11VNC_NCACHE}" != "0" ]]; then
    x11vnc_args+=(-ncache "${X11VNC_NCACHE}" -ncache_cr)
  fi

  emit_log "info" "x11vnc_start" "Starting x11vnc"
  runuser -u "${APP_USER}" -- env DISPLAY="${DISPLAY}" XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR}" x11vnc "${x11vnc_args[@]}" >>"${LOG_DIR}/x11vnc.log" 2>&1 &
  pids+=("$!")
}

start_websockify() {
  emit_log "info" "websockify_start" "Starting websockify"
  websockify --web "${NOVNC_WEB_ROOT}" "${PORT}" "127.0.0.1:${VNC_PORT}" >>"${LOG_DIR}/websockify.log" 2>&1 &
  pids+=("$!")
}

start_application() {
  emit_log "info" "app_launch" "Launching ${APP_NAME}"
  runuser -u "${APP_USER}" -- env DISPLAY="${DISPLAY}" XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR}" dbus-run-session -- /bin/bash /tmp/start-app.sh >>"${LOG_DIR}/app.log" 2>&1 &
  app_pid="$!"
  pids+=("${app_pid}")
}

main() {
  local exit_code=0

  ensure_user
  prepare_directories
  start_log_forwarders
  write_app_script

  start_xvfb
  wait_for_display
  start_window_manager
  set_root_background
  start_window_layout_agent
  start_x11vnc
  wait_for_port 127.0.0.1 "${VNC_PORT}"
  start_websockify
  wait_for_port 127.0.0.1 "${PORT}"
  start_application

  emit_log "info" "session_ready" "Session services are ready"
  wait "${app_pid}" || exit_code=$?
  if (( exit_code == 0 )); then
    emit_log "info" "app_exit" "Application exited cleanly"
  else
    emit_log "error" "app_exit" "Application exited with code ${exit_code}"
  fi
  return "${exit_code}"
}

main "$@"
