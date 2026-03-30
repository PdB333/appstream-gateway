#!/usr/bin/env bash
# Drop-in replacement for xdg-open that forwards URLs and files to the host
# browser via the file-bridge server.
#
# URLs  → sent as-is (the client opens them in a new tab)
# Files → copied to the bridge directory, client downloads them

set -uo pipefail

BRIDGE_DIR="${FILE_BRIDGE_DIR:-/tmp/file-bridge}"
PENDING_DIR="${BRIDGE_DIR}/pending"
FILES_DIR="${BRIDGE_DIR}/files"

TARGET="${1:-}"
if [[ -z "${TARGET}" ]]; then
  echo "Usage: xdg-open <url|file>" >&2
  exit 1
fi

mkdir -p "${PENDING_DIR}" "${FILES_DIR}"

ITEM_ID="$(date +%s%N)-$$"

# Detect if this is a URI or a file path.
# Accept generic URI schemes such as https:, mailto:, lens:, custom+scheme:.
if [[ "${TARGET}" =~ ^[a-zA-Z][a-zA-Z0-9+.-]*: ]]; then
  # It's a URI - forward directly
  cat > "${PENDING_DIR}/${ITEM_ID}.json" <<EOF
{"id":"${ITEM_ID}","type":"url","url":"${TARGET}","ts":$(date +%s)}
EOF
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
