#!/usr/bin/env bash
# Drop-in replacement for xdg-open.
#
# URLs  → opened in the session browser when available, otherwise forwarded
#          to the host via the file-bridge server
# Files → copied to the bridge directory, client downloads them

set -uo pipefail

BRIDGE_DIR="${FILE_BRIDGE_DIR:-/tmp/file-bridge}"
PENDING_DIR="${BRIDGE_DIR}/pending"
FILES_DIR="${BRIDGE_DIR}/files"
SESSION_BROWSER="${SESSION_URL_BROWSER:-}"

TARGET="${1:-}"
if [[ -z "${TARGET}" ]]; then
  echo "Usage: xdg-open <url|file>" >&2
  exit 1
fi

mkdir -p "${PENDING_DIR}" "${FILES_DIR}"

ITEM_ID="$(date +%s%N)-$$"

open_in_session_browser() {
  local url=$1
  local candidate
  local -a browsers=()

  if [[ -n "${SESSION_BROWSER}" ]]; then
    browsers+=("${SESSION_BROWSER}")
  fi
  browsers+=(netsurf-gtk3 netsurf-gtk netsurf firefox brave-browser chromium chromium-browser epiphany)

  for candidate in "${browsers[@]}"; do
    if command -v "${candidate}" >/dev/null 2>&1; then
      nohup "${candidate}" "${url}" >/dev/null 2>&1 &
      return 0
    fi
  done

  return 1
}

# Detect if this is a URI or a file path.
# Accept generic URI schemes such as https:, mailto:, lens:, custom+scheme:.
if [[ "${TARGET}" =~ ^[a-zA-Z][a-zA-Z0-9+.-]*: ]]; then
  # Prefer an in-session browser so links stay inside the desktop session.
  if ! open_in_session_browser "${TARGET}"; then
    # Fallback to host forwarding if no browser is available in-session.
    cat > "${PENDING_DIR}/${ITEM_ID}.json" <<EOF
{"id":"${ITEM_ID}","type":"url","url":"${TARGET}","ts":$(date +%s)}
EOF
  fi
else
  # It's a file path - copy it to the bridge and create a download entry
  if [[ ! -f "${TARGET}" ]]; then
    echo "xdg-open-bridge: file not found: ${TARGET}" >&2
    exit 1
  fi

  FILENAME="$(basename "${TARGET}")"
  EXT="${FILENAME##*.}"
  if [[ "${EXT}" == "${FILENAME}" ]]; then
    EXT=""
  else
    EXT=".${EXT}"
  fi

  BRIDGE_FILE="${FILES_DIR}/${ITEM_ID}${EXT}"
  cp -f "${TARGET}" "${BRIDGE_FILE}"

  cat > "${PENDING_DIR}/${ITEM_ID}.json" <<EOF
{"id":"${ITEM_ID}","type":"file","name":"${FILENAME}","ext":"${EXT}","ts":$(date +%s)}
EOF
fi

exit 0
