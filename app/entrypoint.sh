#!/usr/bin/env bash
set -euo pipefail

APP_SESSION_ID="${APP_SESSION_ID:-unknown}"
APP_USER="${APP_USER:-appuser}"
SESSION_URL_BROWSER="${SESSION_URL_BROWSER:-epiphany-browser}"
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
DISPLAY="${DISPLAY:-:100}"
PORT="${PORT:-8080}"
SCREEN_WIDTH="${SCREEN_WIDTH:-1440}"
SCREEN_HEIGHT="${SCREEN_HEIGHT:-900}"
SCREEN_DEPTH="${SCREEN_DEPTH:-24}"
SCREEN_DPI="${SCREEN_DPI:-96}"
FILE_BRIDGE_PORT="${FILE_BRIDGE_PORT:-9091}"
XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/tmp/runtime-${APP_USER}}"
LOG_DIR="${LOG_DIR:-/tmp/app-web-logs}"
XAUTHORITY="${XAUTHORITY:-${SESSION_HOME}/.Xauthority}"
APP_WINDOW_MODE="${APP_WINDOW_MODE:-auto}"
APP_WINDOW_ELECTRON_FLAGS="${APP_WINDOW_ELECTRON_FLAGS:---kiosk --no-first-run --disable-infobars}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/appimage-launch.sh
source "${SCRIPT_DIR}/lib/appimage-launch.sh"

declare -a pids=()
xpra_pid=""
RESOLVED_COMMAND=""
RESOLVED_WORKDIR=""
RESOLVED_WINDOW_MODE=""

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

to_lower() {
  printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]'
}

looks_like_electron_name() {
  case "$(to_lower "${1:-}")" in
    *electron*|*vscodium*|*codium*|*lens*) return 0 ;;
    *) return 1 ;;
  esac
}

looks_like_electron_artifact() {
  local candidate=${1:-}

  if [[ -z "${candidate}" ]]; then
    return 1
  fi

  if [[ -d "${candidate}" ]]; then
    if find "${candidate}" -maxdepth 4 \( -name 'app.asar' -o -name 'chrome-sandbox' -o -name 'electron' -o -name 'electron.exe' \) -print -quit 2>/dev/null | grep -q .; then
      return 0
    fi
    if find "${candidate}" -maxdepth 4 -type f \( -iname '*electron*' -o -iname '*codium*' -o -iname '*lens*' \) -print -quit 2>/dev/null | grep -q .; then
      return 0
    fi
    return 1
  fi

  if [[ -f "${candidate}" ]]; then
    if file -b "${candidate}" 2>/dev/null | grep -qi 'electron'; then
      return 0
    fi
    if file -b "${candidate}" 2>/dev/null | grep -qi 'ELF'; then
      if grep -a -qi 'electron' "${candidate}" 2>/dev/null; then
        return 0
      fi
    fi
  fi

  return 1
}

resolve_window_mode() {
  local probe=${1:-}
  local requested

  requested="$(to_lower "${APP_WINDOW_MODE}")"
  case "${requested}" in
    auto)
      if looks_like_electron_name "${APP_NAME}" || looks_like_electron_name "${APP_RUN_COMMAND}" || looks_like_electron_name "${probe}" || looks_like_electron_artifact "${probe}"; then
        RESOLVED_WINDOW_MODE="electron"
      else
        RESOLVED_WINDOW_MODE="immersive"
      fi
      ;;
    electron|immersive)
      RESOLVED_WINDOW_MODE="${requested}"
      ;;
    *)
      RESOLVED_WINDOW_MODE="immersive"
      ;;
  esac

  emit_log "info" "window_mode" "Resolved window mode: ${RESOLVED_WINDOW_MODE}"
}

cleanup() {
  local exit_code=$?

  emit_log "info" "session_stopping" "Stopping session"
  if [[ -n "${xpra_pid}" ]]; then
    kill "${xpra_pid}" 2>/dev/null || true
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

  # Ensure the OS home directory exists and points to SESSION_HOME
  # (ReadonlyRootfs means /home is a tmpfs, so we must recreate it each boot)
  local os_home
  os_home="$(eval echo "~${APP_USER}" 2>/dev/null || echo "/home/${APP_USER}")"
  if [[ "${os_home}" != "${SESSION_HOME}" ]]; then
    mkdir -p "${os_home}" 2>/dev/null || true
    # Bind-link key dot-directories so apps writing to the OS home find writable storage
    for d in .config .cache .local .pki .kube .k8slens .mozilla .brave .joplin .logseq; do
      mkdir -p "${SESSION_HOME}/${d}" "${os_home}/${d}" 2>/dev/null || true
      mount --bind "${SESSION_HOME}/${d}" "${os_home}/${d}" 2>/dev/null || \
        ln -sfn "${SESSION_HOME}/${d}" "${os_home}/${d}" 2>/dev/null || true
    done
    chown -R "${APP_USER}:${APP_USER}" "${os_home}" 2>/dev/null || true
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
    "${SESSION_HOME}/.local/share/applications" \
    "${SESSION_HOME}/.pki/nssdb" \
    "${SESSION_HOME}/Downloads" \
    "${XDG_RUNTIME_DIR}" \
    "${LOG_DIR}" \
    /tmp \
    /tmp/.X11-unix
  touch "${LOG_DIR}/xpra.log" "${LOG_DIR}/app.log"
  touch "${LOG_DIR}/file-bridge.log"
  touch "${XAUTHORITY}" 2>/dev/null || true
  chmod 1777 /tmp /tmp/.X11-unix
  chmod 0700 "${XDG_RUNTIME_DIR}"

  # Ensure /dev/shm exists and is writable (critical for Chromium/Electron apps)
  if [[ ! -d /dev/shm ]]; then
    mkdir -p /dev/shm 2>/dev/null || true
  fi
  chmod 1777 /dev/shm 2>/dev/null || true

  chown -R "${APP_USER}:${APP_USER}" "${APP_CACHE_DIR}" "${DATA_DIR}" "${XDG_RUNTIME_DIR}" "${SESSION_HOME}" "${LOG_DIR}"
  chown "${APP_USER}:${APP_USER}" "${XAUTHORITY}" 2>/dev/null || true

  # Rebuild GDK pixbuf cache at runtime into a writable location
  # (ReadonlyRootfs means the default cache path is not writable)
  local pixbuf_cache="/tmp/gdk-pixbuf-loaders.cache"

  # Find the pixbuf query-loaders binary (not always in PATH on Ubuntu 22.04)
  local pixbuf_ql=""
  pixbuf_ql="$(find /usr/lib -name 'gdk-pixbuf-query-loaders*' -type f 2>/dev/null | head -1)"
  if [[ -z "${pixbuf_ql}" ]]; then
    command -v gdk-pixbuf-query-loaders >/dev/null 2>&1 && pixbuf_ql="gdk-pixbuf-query-loaders"
  fi

  # Find the system loaders dir and cache (arch-independent)
  local pixbuf_loaders_dir pixbuf_sys_cache
  pixbuf_loaders_dir="$(find /usr/lib -path '*/gdk-pixbuf-2.0/*/loaders' -type d 2>/dev/null | head -1)"
  pixbuf_sys_cache="$(find /usr/lib -name 'loaders.cache' -path '*/gdk-pixbuf-2.0/*' 2>/dev/null | head -1)"

  # Debug: check if system loaders exist
  if [[ -n "${pixbuf_loaders_dir}" ]]; then
    local loader_count
    loader_count="$(ls -1 "${pixbuf_loaders_dir}"/libpixbufloader-*.so 2>/dev/null | wc -l)"
    emit_log "info" "pixbuf_loaders" "Found ${loader_count} pixbuf loaders in ${pixbuf_loaders_dir}"
    if ls "${pixbuf_loaders_dir}"/libpixbufloader-png.so >/dev/null 2>&1; then
      emit_log "info" "pixbuf_png_ok" "PNG pixbuf loader found"
    else
      emit_log "error" "pixbuf_png_missing" "PNG pixbuf loader NOT found"
    fi
  else
    emit_log "warn" "pixbuf_loaders_dir_missing" "Pixbuf loaders directory not found"
  fi

  # Generate runtime cache
  if [[ -n "${pixbuf_ql}" ]]; then
    "${pixbuf_ql}" > "${pixbuf_cache}" 2>/dev/null || true
    if [[ -s "${pixbuf_cache}" ]]; then
      export GDK_PIXBUF_MODULE_FILE="${pixbuf_cache}"
      emit_log "info" "pixbuf_cache" "Pixbuf cache: ${pixbuf_cache} ($(wc -l < "${pixbuf_cache}") lines, $(grep -c 'png' "${pixbuf_cache}" 2>/dev/null || echo 0) PNG refs)"
    else
      emit_log "warn" "pixbuf_cache_empty" "Runtime pixbuf cache is empty"
      if [[ -n "${pixbuf_sys_cache}" ]]; then
        export GDK_PIXBUF_MODULE_FILE="${pixbuf_sys_cache}"
        emit_log "info" "pixbuf_cache_fallback" "Using system cache: ${pixbuf_sys_cache}"
      fi
    fi
    # Also try system cache update
    "${pixbuf_ql}" --update-cache 2>/dev/null || true
  elif [[ -n "${pixbuf_sys_cache}" ]]; then
    export GDK_PIXBUF_MODULE_FILE="${pixbuf_sys_cache}"
    emit_log "info" "pixbuf_cache_system" "Using system cache (query-loaders not found): ${pixbuf_sys_cache}"
  fi
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
  tail_component_log "xpra" "${LOG_DIR}/xpra.log"
  tail_component_log "app" "${LOG_DIR}/app.log"
  tail_component_log "file_bridge" "${LOG_DIR}/file-bridge.log"
}

wait_for_display() {
  local retries=60

  until runuser -u "${APP_USER}" -- env DISPLAY="${DISPLAY}" HOME="${SESSION_HOME}" XAUTHORITY="${XAUTHORITY}" xdpyinfo >/dev/null 2>&1; do
    retries=$((retries - 1))
    if (( retries == 0 )); then
      emit_log "error" "display_not_ready" "Display did not become ready"
      return 1
    fi
    sleep 0.5
  done
}

apply_display_geometry() {
  local width=${1:-${SCREEN_WIDTH}}
  local height=${2:-${SCREEN_HEIGHT}}
  local mode_name="${width}x${height}"

  # Use cvt to generate proper modeline, then add and switch to the mode.
  # xrandr --fb alone doesn't change the screen size that apps actually see on Xvfb.
  # We need proper RandR mode creation + output switching.
  local xrandr_script
  xrandr_script="$(cat <<'XEOF'
WIDTH=__WIDTH__
HEIGHT=__HEIGHT__
MODE_NAME=__MODE_NAME__

OUTPUT=$(xrandr 2>/dev/null | awk '/ connected/{print $1; exit}')
OUTPUT=${OUTPUT:-screen}

# Check if the mode already exists and is active
CURRENT=$(xrandr 2>/dev/null | awk '/\*/{print $1; exit}')
if [ "${CURRENT}" = "${MODE_NAME}" ]; then
  exit 0
fi

# Try simple -s first (works if Xvfb was started at this resolution)
xrandr -s "${MODE_NAME}" 2>/dev/null && exit 0

# Create mode with dummy modeline (sufficient for Xvfb virtual displays)
xrandr --newmode "${MODE_NAME}" 0 ${WIDTH} ${WIDTH} ${WIDTH} ${WIDTH} ${HEIGHT} ${HEIGHT} ${HEIGHT} ${HEIGHT} 2>/dev/null || true
xrandr --addmode "${OUTPUT}" "${MODE_NAME}" 2>/dev/null || true
xrandr --output "${OUTPUT}" --mode "${MODE_NAME}" 2>/dev/null || \
  xrandr --fb "${MODE_NAME}" 2>/dev/null || true
XEOF
  )"

  # Substitute values
  xrandr_script="${xrandr_script//__WIDTH__/${width}}"
  xrandr_script="${xrandr_script//__HEIGHT__/${height}}"
  xrandr_script="${xrandr_script//__MODE_NAME__/${mode_name}}"

  runuser -u "${APP_USER}" -- env DISPLAY="${DISPLAY}" XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR}" sh -c "${xrandr_script}"
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

validate_binary() {
  local file_path=$1
  local file_size

  if [[ ! -f "${file_path}" ]]; then
    emit_log "error" "artifact_missing" "Downloaded file does not exist: ${file_path}"
    return 1
  fi

  file_size="$(stat -c%s "${file_path}" 2>/dev/null || echo 0)"
  if (( file_size < 1024 )); then
    emit_log "error" "artifact_too_small" "Downloaded file is only ${file_size} bytes (likely an error page, not a binary): ${file_path}"
    rm -f "${file_path}"
    return 1
  fi

  local magic
  magic="$(head -c 4 "${file_path}" | od -A n -t x1 | tr -d ' ')"
  case "${magic}" in
    7f454c46) ;; # ELF binary - valid
    41490200) ;; # AppImage type 2 - valid
    *)
      # Check if it's text/HTML (bad download)
      if file "${file_path}" 2>/dev/null | grep -qi "text\|html\|xml"; then
        emit_log "error" "artifact_not_binary" "Downloaded file is text/HTML, not a binary. The URL likely requires authentication or returned an error page."
        local preview
        preview="$(head -c 200 "${file_path}" 2>/dev/null)"
        emit_log "error" "artifact_preview" "First 200 bytes: ${preview}"
        rm -f "${file_path}"
        return 1
      fi
      emit_log "warn" "artifact_unknown_format" "File magic ${magic} is not standard ELF/AppImage, proceeding anyway"
      ;;
  esac

  return 0
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

  if [[ -f "${target_path}" ]]; then
    # Validate cached file - remove if corrupt
    if ! validate_binary "${target_path}"; then
      emit_log "warn" "cache_invalidated" "Cached artifact was invalid, re-downloading"
    fi
  fi

  if [[ ! -f "${target_path}" ]]; then
    emit_log "info" "artifact_download_start" "Downloading ${url}"
    curl --fail --silent --show-error --location \
      --retry 3 --retry-delay 2 \
      --connect-timeout 30 --max-time 600 \
      "${url}" --output "${target_path}.tmp"
    if [[ -n "${sha256_value}" ]]; then
      printf '%s  %s\n' "${sha256_value}" "${target_path}.tmp" | sha256sum --check --status
    fi
    if ! validate_binary "${target_path}.tmp"; then
      emit_log "error" "artifact_download_invalid" "Downloaded file from ${url} is not a valid binary"
      return 1
    fi
    mv "${target_path}.tmp" "${target_path}"
    emit_log "info" "artifact_download_complete" "Downloaded $(stat -c%s "${target_path}" 2>/dev/null || echo '?') bytes to ${target_path}"
  else
    emit_log "info" "artifact_cache_hit" "Using cached artifact: ${target_path} ($(stat -c%s "${target_path}" 2>/dev/null || echo '?') bytes)"
  fi

  printf '%s' "${target_path}"
}

prepare_appimage() {
  local appimage_path=$1
  local staged_path extract_dir

  resolve_appimage_launch_spec \
    "${APP_CACHE_DIR}" \
    "${APP_DOWNLOAD_DIR}" \
    "${appimage_path}" \
    "${APPIMAGE_EXTRACT_AND_RUN}" \
    "${APP_ARGS}" \
    "${APP_WORKDIR}"

  staged_path="${APPIMAGE_STAGED_PATH}"
  extract_dir="${APPIMAGE_EXTRACT_DIR}"

  if [[ ! -f "${appimage_path}" ]]; then
    emit_log "error" "appimage_source_missing" "Source AppImage not found: ${appimage_path}"
    return 1
  fi

  # If extract-and-run is enabled, pre-extract the AppImage now.
  # This avoids the AppImage runtime overriding LD_LIBRARY_PATH at launch,
  # which breaks system GTK pixbuf loaders and causes file dialog crashes.
  if [[ "${APPIMAGE_EXTRACT_AND_RUN}" == "1" ]]; then
    mkdir -p "$(dirname "${extract_dir}")"

    if [[ -x "${extract_dir}/AppRun" ]]; then
      emit_log "info" "appimage_extract_cache_hit" "Using extracted AppImage cache at ${extract_dir}"
      printf '%s' "${extract_dir}"
      return 0
    fi

    if [[ ! -f "${staged_path}" ]]; then
      cp -f "${appimage_path}" "${staged_path}"
    fi
    chmod 0755 "${staged_path}"
    chown "${APP_USER}:${APP_USER}" "${staged_path}" 2>/dev/null || true

    if [[ ! -x "${staged_path}" ]]; then
      emit_log "error" "appimage_not_executable" "Staged AppImage is not executable: ${staged_path}"
      return 1
    fi

    if [[ ! -d "${extract_dir}" ]]; then
      emit_log "info" "appimage_extract" "Pre-extracting AppImage to ${extract_dir}"
      local extract_tmp="${APP_DOWNLOAD_DIR}/.extract-tmp-$$"
      mkdir -p "${extract_tmp}"
      (cd "${extract_tmp}" && "${staged_path}" --appimage-extract) >/dev/null 2>&1 || true
      if [[ -d "${extract_tmp}/squashfs-root" ]]; then
        mv "${extract_tmp}/squashfs-root" "${extract_dir}"
        rm -rf "${extract_tmp}"
        chmod -R u+rw "${extract_dir}" 2>/dev/null || true
        chown -R "${APP_USER}:${APP_USER}" "${extract_dir}" 2>/dev/null || true
        emit_log "info" "appimage_extracted" "AppImage extracted to ${extract_dir}"
      else
        emit_log "warn" "appimage_extract_failed" "AppImage extraction failed, falling back to --appimage-extract-and-run"
        rm -rf "${extract_tmp}"
        printf '%s' "${staged_path}"
        return 0
      fi
    fi

    printf '%s' "${extract_dir}"
    return 0
  fi

  cp -f "${appimage_path}" "${staged_path}"
  chmod 0755 "${staged_path}"
  chown "${APP_USER}:${APP_USER}" "${staged_path}" 2>/dev/null || true

  if [[ ! -x "${staged_path}" ]]; then
    emit_log "error" "appimage_not_executable" "Staged AppImage is not executable: ${staged_path}"
    return 1
  fi

  emit_log "info" "appimage_staged" "AppImage staged at ${staged_path} ($(stat -c%s "${staged_path}" 2>/dev/null || echo '?') bytes)"
  printf '%s' "${staged_path}"
}

prepare_archive() {
  local archive_path=$1
  local cache_key extract_dir entrypoint_path

  cache_key="$(printf '%s' "${archive_path}:${APP_ARCHIVE_ENTRYPOINT}:${APP_ARCHIVE_STRIP_COMPONENTS}" | sha256sum | awk '{print $1}')"
  extract_dir="${APP_CACHE_DIR}/extract-${cache_key}"
  entrypoint_path="${extract_dir}/${APP_ARCHIVE_ENTRYPOINT}"

  extract_archive_once() {
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
  }

  if [[ ! -d "${extract_dir}" ]]; then
    extract_archive_once
  fi

  if [[ ! -x "${entrypoint_path}" ]]; then
    emit_log "warn" "archive_entrypoint_missing" "Archive entrypoint missing at ${entrypoint_path}, rebuilding cache"
    rm -rf "${extract_dir}"
    extract_archive_once
  fi

  if [[ ! -x "${entrypoint_path}" ]]; then
    emit_log "error" "archive_entrypoint_invalid" "Archive entrypoint still missing or not executable at ${entrypoint_path}"
    return 1
  fi

  printf '%s' "${extract_dir}"
}

emit_launch_stage() {
  emit_log "info" "launch_stage" "$1"
}

resolve_launch_spec() {
  local artifact_path archive_dir quoted_path window_probe=""

  RESOLVED_WORKDIR="${APP_WORKDIR}"

  case "${APP_SOURCE_TYPE}" in
    command)
      if [[ -z "${APP_RUN_COMMAND}" ]]; then
        emit_log "error" "launch_spec_invalid" "APP_RUN_COMMAND is required for command sources"
        return 1
      fi
      emit_launch_stage "resolve command launch"
      RESOLVED_COMMAND="${APP_RUN_COMMAND} ${APP_ARGS}"
      window_probe="${APP_RUN_COMMAND}"
      ;;
    binary-path)
      if [[ -z "${APP_SOURCE_PATH}" ]]; then
        emit_log "error" "launch_spec_invalid" "APP_SOURCE_PATH is required for binary-path sources"
        return 1
      fi
      emit_launch_stage "resolve binary launch"
      printf -v quoted_path '%q' "${APP_SOURCE_PATH}"
      RESOLVED_COMMAND="${quoted_path} ${APP_ARGS}"
      window_probe="${APP_SOURCE_PATH}"
      ;;
    appimage-file)
      if [[ -z "${APP_SOURCE_PATH}" ]]; then
        emit_log "error" "launch_spec_invalid" "APP_SOURCE_PATH is required for appimage-file sources"
        return 1
      fi
      emit_launch_stage "resolve appimage launch"
      artifact_path="$(prepare_appimage "${APP_SOURCE_PATH}")"
      window_probe="${artifact_path}"
      if [[ "${APPIMAGE_EXTRACT_AND_RUN}" == "1" && -d "${artifact_path}" ]]; then
        RESOLVED_WORKDIR="${artifact_path}"
        printf -v quoted_dir '%q' "${artifact_path}"
        RESOLVED_COMMAND="APPDIR=${quoted_dir} ./AppRun ${APP_ARGS}"
      else
        printf -v quoted_path '%q' "${artifact_path}"
        RESOLVED_COMMAND="${quoted_path} ${APP_ARGS}"
      fi
      ;;
    appimage-url)
      if [[ -z "${APP_SOURCE_URL}" ]]; then
        emit_log "error" "launch_spec_invalid" "APP_SOURCE_URL is required for appimage-url sources"
        return 1
      fi
      emit_launch_stage "download appimage"
      artifact_path="$(download_artifact "${APP_SOURCE_URL}" "${APP_SHA256}" ".AppImage")"
      emit_launch_stage "prepare appimage"
      artifact_path="$(prepare_appimage "${artifact_path}")"
      window_probe="${artifact_path}"
      if [[ "${APPIMAGE_EXTRACT_AND_RUN}" == "1" && -d "${artifact_path}" ]]; then
        RESOLVED_WORKDIR="${artifact_path}"
        printf -v quoted_dir '%q' "${artifact_path}"
        RESOLVED_COMMAND="APPDIR=${quoted_dir} ./AppRun ${APP_ARGS}"
      else
        printf -v quoted_path '%q' "${artifact_path}"
        RESOLVED_COMMAND="${quoted_path} ${APP_ARGS}"
      fi
      ;;
    archive-url)
      if [[ -z "${APP_SOURCE_URL}" || -z "${APP_ARCHIVE_ENTRYPOINT}" ]]; then
        emit_log "error" "launch_spec_invalid" "APP_SOURCE_URL and APP_ARCHIVE_ENTRYPOINT are required for archive-url sources"
        return 1
      fi
      emit_launch_stage "download archive"
      artifact_path="$(download_artifact "${APP_SOURCE_URL}" "${APP_SHA256}" ".archive")"
      emit_launch_stage "extract archive"
      archive_dir="$(prepare_archive "${artifact_path}")"
      window_probe="${archive_dir}/${APP_ARCHIVE_ENTRYPOINT}"
      if [[ -z "${RESOLVED_WORKDIR}" ]]; then
        RESOLVED_WORKDIR="${archive_dir}"
      fi
      emit_launch_stage "build archive launch command"
      printf -v quoted_path '%q' "${archive_dir}/${APP_ARCHIVE_ENTRYPOINT}"
      RESOLVED_COMMAND="${quoted_path} ${APP_ARGS}"
      ;;
    *)
      emit_log "error" "launch_spec_invalid" "Unsupported source type ${APP_SOURCE_TYPE}"
      return 1
      ;;
  esac

  resolve_window_mode "${window_probe}"
  if [[ "${RESOLVED_WINDOW_MODE}" == "electron" ]]; then
    case "${APP_SOURCE_TYPE}" in
      command)
        RESOLVED_COMMAND="${APP_RUN_COMMAND} ${APP_WINDOW_ELECTRON_FLAGS} ${APP_ARGS}"
        ;;
      binary-path)
        printf -v quoted_path '%q' "${APP_SOURCE_PATH}"
        RESOLVED_COMMAND="${quoted_path} ${APP_WINDOW_ELECTRON_FLAGS} ${APP_ARGS}"
        ;;
      appimage-file|appimage-url)
        if [[ "${APPIMAGE_EXTRACT_AND_RUN}" == "1" && -n "${artifact_path:-}" && -d "${artifact_path}" ]]; then
          printf -v quoted_dir '%q' "${artifact_path}"
          RESOLVED_COMMAND="APPDIR=${quoted_dir} ./AppRun ${APP_WINDOW_ELECTRON_FLAGS} ${APP_ARGS}"
        else
          printf -v quoted_path '%q' "${artifact_path}"
          RESOLVED_COMMAND="${quoted_path} ${APP_WINDOW_ELECTRON_FLAGS} ${APP_ARGS}"
        fi
        ;;
      archive-url)
        printf -v quoted_path '%q' "${archive_dir}/${APP_ARCHIVE_ENTRYPOINT}"
        RESOLVED_COMMAND="${quoted_path} ${APP_WINDOW_ELECTRON_FLAGS} ${APP_ARGS}"
        ;;
    esac
  fi
}

write_app_script() {
  resolve_launch_spec

  cat > /tmp/start-app.sh <<EOF
#!/usr/bin/env bash
set -uo pipefail
export HOME="${SESSION_HOME}"
export USER="${APP_USER}"
export LOGNAME="${APP_USER}"
export XAUTHORITY="${XAUTHORITY}"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR}"
export XDG_CONFIG_HOME="${SESSION_HOME}/.config"
export XDG_CACHE_HOME="${SESSION_HOME}/.cache"
export XDG_DATA_HOME="${SESSION_HOME}/.local/share"
export XDG_CURRENT_DESKTOP="Xpra"
export NO_AT_BRIDGE=1
export LIBGL_ALWAYS_SOFTWARE="${LIBGL_ALWAYS_SOFTWARE:-1}"
export MESA_LOADER_DRIVER_OVERRIDE="${MESA_LOADER_DRIVER_OVERRIDE:-llvmpipe}"
export PATH="/tmp:\${PATH}"
export ELECTRON_DISABLE_SANDBOX=1
export ELECTRON_NO_ATTACH_CONSOLE=1
export ELECTRON_DISABLE_GPU=\${ELECTRON_DISABLE_GPU:-0}
export CHROME_DEVEL_SANDBOX=""
export GDK_SCALE=\${GDK_SCALE:-1}
export GDK_DPI_SCALE=\${GDK_DPI_SCALE:-1}
export QT_AUTO_SCREEN_SCALE_FACTOR=\${QT_AUTO_SCREEN_SCALE_FACTOR:-0}
export QT_SCALE_FACTOR=\${QT_SCALE_FACTOR:-1}
export XCURSOR_SIZE=\${XCURSOR_SIZE:-24}
export GTK_THEME=\${GTK_THEME:-Adwaita}
export SESSION_URL_BROWSER="${SESSION_URL_BROWSER}"
# Force GDK pixbuf loader paths — critical for GTK file dialogs in Electron/AppImage apps.
# Discover paths dynamically (works across architectures).
_PB_DIR=\$(find /usr/lib -path '*/gdk-pixbuf-2.0/*/loaders' -type d 2>/dev/null | head -1)
[[ -n "\${_PB_DIR}" ]] && export GDK_PIXBUF_MODULEDIR="\${_PB_DIR}"
if [[ -f /tmp/gdk-pixbuf-loaders.cache ]]; then
  export GDK_PIXBUF_MODULE_FILE=/tmp/gdk-pixbuf-loaders.cache
else
  _PB_CACHE=\$(find /usr/lib -name 'loaders.cache' -path '*/gdk-pixbuf-2.0/*' 2>/dev/null | head -1)
  [[ -n "\${_PB_CACHE}" ]] && export GDK_PIXBUF_MODULE_FILE="\${_PB_CACHE}"
fi
mkdir -p "\${XDG_CONFIG_HOME}" "\${XDG_CACHE_HOME}" "\${XDG_DATA_HOME}" "\${HOME}"
mkdir -p "\${HOME}/.config" "\${HOME}/.local/share" "\${HOME}/.cache"
mkdir -p "\${HOME}/.kube" "\${HOME}/.k8slens" "\${HOME}/.pki/nssdb"
EOF

  if [[ -n "${RESOLVED_WORKDIR}" ]]; then
    printf 'cd -- %q\n' "${RESOLVED_WORKDIR}" >> /tmp/start-app.sh
  fi
  if [[ -n "${APP_PRE_LAUNCH_COMMAND}" ]]; then
    printf 'APP_PRE_LAUNCH_COMMAND=%q\n' "${APP_PRE_LAUNCH_COMMAND}" >> /tmp/start-app.sh
    printf '/bin/bash -lc "$APP_PRE_LAUNCH_COMMAND" || true\n' >> /tmp/start-app.sh
  fi
  printf 'APP_LAUNCH_COMMAND=%q\n' "${RESOLVED_COMMAND}" >> /tmp/start-app.sh

  # Create a GTK pixbuf wrapper that ensures loaders are found even if
  # AppImage/AppRun modifies LD_LIBRARY_PATH at launch
  cat >> /tmp/start-app.sh <<'WRAPEOF'
# Write a wrapper that re-exports pixbuf paths — AppRun scripts often
# override LD_LIBRARY_PATH which makes GTK unable to find PNG/SVG loaders
_PIXBUF_WRAPPER=/tmp/_gtk_pixbuf_wrapper.sh
cat > "${_PIXBUF_WRAPPER}" <<'INNEREOF'
#!/bin/bash
# Re-force system pixbuf loaders regardless of what AppRun changed
_D=$(find /usr/lib -path '*/gdk-pixbuf-2.0/*/loaders' -type d 2>/dev/null | head -1)
[ -n "$_D" ] && export GDK_PIXBUF_MODULEDIR="$_D"
if [ -f /tmp/gdk-pixbuf-loaders.cache ]; then
  export GDK_PIXBUF_MODULE_FILE=/tmp/gdk-pixbuf-loaders.cache
else
  _C=$(find /usr/lib -name 'loaders.cache' -path '*/gdk-pixbuf-2.0/*' 2>/dev/null | head -1)
  [ -n "$_C" ] && export GDK_PIXBUF_MODULE_FILE="$_C"
fi
exec "$@"
INNEREOF
chmod +x "${_PIXBUF_WRAPPER}"

# Disabled for extracted AppImages: wrapping AppRun changes $0 and breaks APPDIR detection.
if false && echo "${APP_LAUNCH_COMMAND}" | grep -q "AppRun\|appimage-extract-and-run"; then
  APP_LAUNCH_COMMAND="${_PIXBUF_WRAPPER} ${APP_LAUNCH_COMMAND}"
fi
WRAPEOF

  printf 'exec /bin/bash -lc "$APP_LAUNCH_COMMAND" >> %q 2>&1\n' "${LOG_DIR}/app.log" >> /tmp/start-app.sh

  chmod 0755 /tmp/start-app.sh
}

start_xvfb() {
  # Start Xvfb at the actual requested resolution — NOT the max.
  # Starting at 3840x2160 causes apps to render at that huge resolution,
  # and noVNC scales it down making everything tiny.
  # For dynamic resize, we create new xrandr modes on the fly.
  local xvfb_width="${SCREEN_WIDTH}"
  local xvfb_height="${SCREEN_HEIGHT}"

  emit_log "info" "xvfb_start" "Starting Xvfb at ${xvfb_width}x${xvfb_height}x${SCREEN_DEPTH}"
  runuser -u "${APP_USER}" -- env DISPLAY="${DISPLAY}" HOME="${SESSION_HOME}" XAUTHORITY="${XAUTHORITY}" Xvfb "${DISPLAY}" \
    -screen 0 "${xvfb_width}x${xvfb_height}x${SCREEN_DEPTH}" \
    +extension RANDR +extension GLX \
    -dpi "${SCREEN_DPI}" \
    -ac -nolisten tcp >>"${LOG_DIR}/xvfb.log" 2>&1 &
  pids+=("$!")
}

start_window_manager() {
  if [[ "${RESOLVED_WINDOW_MODE:-immersive}" != "immersive" ]]; then
    return
  fi

  emit_log "info" "openbox_start" "Starting openbox"
  runuser -u "${APP_USER}" -- env \
    DISPLAY="${DISPLAY}" \
    HOME="${SESSION_HOME}" \
    XAUTHORITY="${XAUTHORITY}" \
    XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR}" \
    XDG_CONFIG_HOME="${SESSION_HOME}/.config" \
    XDG_CACHE_HOME="${SESSION_HOME}/.cache" \
    XDG_DATA_HOME="${SESSION_HOME}/.local/share" \
    openbox --sm-disable >>"${LOG_DIR}/openbox.log" 2>&1 &
  pids+=("$!")
}

set_root_background() {
  runuser -u "${APP_USER}" -- env DISPLAY="${DISPLAY}" HOME="${SESSION_HOME}" XAUTHORITY="${XAUTHORITY}" XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR}" xsetroot -solid "#050505" >>"${LOG_DIR}/window-agent.log" 2>&1 || true
}

start_window_layout_agent() {
  if [[ "${RESOLVED_WINDOW_MODE:-immersive}" != "immersive" ]]; then
    return
  fi

  emit_log "info" "window_agent_start" "Starting immersive window layout agent"

  cat > /tmp/window-layout-agent.sh <<EOF
#!/usr/bin/env bash
set -uo pipefail
export DISPLAY="${DISPLAY}"
export HOME="${SESSION_HOME}"
export XAUTHORITY="${XAUTHORITY}"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR}"
fallback_width="${SCREEN_WIDTH}"
fallback_height="${SCREEN_HEIGHT}"

# Track which windows we already maximized so we don't fight with user resizes
declare -A handled_windows

while true; do
  screen_size="\$(xdpyinfo 2>/dev/null | awk '/dimensions:/ { print \$2; exit }')"
  screen_width="\${screen_size%x*}"
  screen_height="\${screen_size#*x}"
  [[ -z "\${screen_width}" || "\${screen_width}" == "\${screen_size}" ]] && screen_width="\${fallback_width}"
  [[ -z "\${screen_height}" || "\${screen_height}" == "\${screen_size}" ]] && screen_height="\${fallback_height}"

  current_windows=""
  while read -r window_id desktop host window_class rest; do
    [[ -z "\${window_id}" ]] && continue
    current_windows="\${current_windows} \${window_id}"

    # Skip WM windows and already-handled windows
    case "\${window_class}" in
      *Openbox*|*openbox*|*Desktop*|*desktop_window*) continue ;;
    esac

    # Skip dialog/transient/splash windows - let the app manage them
    win_type="\$(xprop -id "\${window_id}" _NET_WM_WINDOW_TYPE 2>/dev/null || true)"
    case "\${win_type}" in
      *DIALOG*|*SPLASH*|*POPUP*|*TOOLTIP*|*NOTIFICATION*|*UTILITY*|*MENU*|*DROPDOWN*|*COMBO*)
        continue ;;
    esac

    # Only maximize a window once (first time we see it)
    if [[ -n "\${handled_windows[\${window_id}]+x}" ]]; then
      continue
    fi

    xprop -id "\${window_id}" -f _MOTIF_WM_HINTS 32c -set _MOTIF_WM_HINTS "2, 0, 0, 0, 0" >/dev/null 2>&1 || true
    wmctrl -i -r "\${window_id}" -b add,maximized_vert,maximized_horz >/dev/null 2>&1 || true
    wmctrl -i -r "\${window_id}" -e "0,0,0,\${screen_width},\${screen_height}" >/dev/null 2>&1 || true
    wmctrl -i -a "\${window_id}" >/dev/null 2>&1 || true
    handled_windows["\${window_id}"]=1
  done < <(wmctrl -lx 2>/dev/null)

  # Prune closed windows from the handled set
  for wid in "\${!handled_windows[@]}"; do
    if [[ "\${current_windows}" != *"\${wid}"* ]]; then
      unset handled_windows["\${wid}"]
    fi
  done

  sleep 0.5
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

start_file_bridge() {
  local bridge_dir="/tmp/file-bridge"
  mkdir -p "${bridge_dir}/pending" "${bridge_dir}/files"
  chown -R "${APP_USER}:${APP_USER}" "${bridge_dir}"

  # Install our xdg-open override ahead of the system one in PATH
  cp /app/xdg-open-bridge.sh /tmp/xdg-open
  chmod 0755 /tmp/xdg-open
  chown "${APP_USER}:${APP_USER}" /tmp/xdg-open

  # Start the Python file bridge server
  emit_log "info" "file_bridge_start" "Starting file bridge on port ${FILE_BRIDGE_PORT:-9091}"
  runuser -u "${APP_USER}" -- env \
    DISPLAY="${DISPLAY}" \
    XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR}" \
    FILE_BRIDGE_PORT="${FILE_BRIDGE_PORT}" \
    FILE_BRIDGE_DIR="${bridge_dir}" \
    SESSION_HOME="${SESSION_HOME}" \
    python3 -u /app/file-bridge.py >>"${LOG_DIR}/file-bridge.log" 2>&1 &
  pids+=("$!")
}

build_xpra_args() {
  XPRA_ARGS=(
    start
    "${DISPLAY}"
    "--bind-tcp=0.0.0.0:${PORT}"
    "--html=on"
    "--daemon=no"
    "--dpi=${SCREEN_DPI}"
    "--resize-display=yes"
    "--exit-with-children=yes"
    "--clipboard=yes"
    "--file-transfer=yes"
    "--notifications=yes"
    "--start-child=dbus-run-session -- /bin/bash /tmp/start-app.sh"
  )
}

start_xpra_server() {
  emit_log "info" "xpra_start" "Starting Xpra on port ${PORT}"
  build_xpra_args
  runuser -u "${APP_USER}" -- env \
    DISPLAY="${DISPLAY}" \
    HOME="${SESSION_HOME}" \
    XAUTHORITY="${XAUTHORITY}" \
    USER="${APP_USER}" \
    LOGNAME="${APP_USER}" \
    XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR}" \
    XDG_CONFIG_HOME="${SESSION_HOME}/.config" \
    XDG_CACHE_HOME="${SESSION_HOME}/.cache" \
    XDG_DATA_HOME="${SESSION_HOME}/.local/share" \
    xpra "${XPRA_ARGS[@]}" >>"${LOG_DIR}/xpra.log" 2>&1 &
  xpra_pid="$!"
  pids+=("${xpra_pid}")
}

start_dbus() {
  # Start a system D-Bus daemon if the socket doesn't exist yet
  # Many Electron/desktop apps expect a system bus for notifications, secrets, etc.
  if [[ ! -S /run/dbus/system_bus_socket ]]; then
    mkdir -p /run/dbus 2>/dev/null || true
    # Ensure machine-id exists (required by dbus-daemon --system)
    # Rootfs is read-only so we generate it into /run and bind-mount or symlink
    if [[ ! -f /etc/machine-id ]] || [[ ! -s /etc/machine-id ]]; then
      dbus-uuidgen > /run/machine-id 2>/dev/null || true
      mount --bind /run/machine-id /etc/machine-id 2>/dev/null || \
        ln -sf /run/machine-id /etc/machine-id 2>/dev/null || true
    fi
    if command -v dbus-daemon >/dev/null 2>&1; then
      dbus-daemon --system --nofork --nopidfile 2>/dev/null &
      pids+=("$!")
      # Give it a moment to create the socket
      local retries=10
      while [[ ! -S /run/dbus/system_bus_socket ]] && (( retries > 0 )); do
        sleep 0.1
        retries=$((retries - 1))
      done
      if [[ -S /run/dbus/system_bus_socket ]]; then
        emit_log "info" "dbus_started" "System D-Bus daemon started"
      else
        emit_log "warn" "dbus_failed" "System D-Bus daemon did not create socket in time"
      fi
    else
      emit_log "warn" "dbus_missing" "dbus-daemon not found, some apps may not function correctly"
    fi
  fi
}

main() {
  local exit_code=0

  ensure_user
  prepare_directories
  start_log_forwarders
  write_app_script

  start_dbus
  start_xpra_server
  wait_for_display || emit_log "warn" "display_not_ready" "Continuing despite display readiness check failure"
  if [[ "${RESOLVED_WINDOW_MODE}" == "immersive" ]]; then
    start_window_manager
    set_root_background
    start_window_layout_agent
  fi
  wait_for_port 127.0.0.1 "${PORT}"
  start_file_bridge
  wait_for_port 127.0.0.1 "${FILE_BRIDGE_PORT}"

  emit_log "info" "session_ready" "Session services are ready"
  wait "${xpra_pid}" || exit_code=$?
  if (( exit_code == 0 )); then
    emit_log "info" "app_exit" "Application exited cleanly"
  else
    emit_log "error" "app_exit" "Application exited with code ${exit_code}"
  fi
  return "${exit_code}"
}

if [[ "${APP_ENTRYPOINT_LIBRARY_MODE:-0}" != "1" ]]; then
  main "$@"
fi
