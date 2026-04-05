#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

export APP_ENTRYPOINT_LIBRARY_MODE=1
# shellcheck source=../entrypoint.sh
source "${ROOT_DIR}/entrypoint.sh"

assert_eq() {
  local actual=$1
  local expected=$2
  local message=$3
  if [[ "${actual}" != "${expected}" ]]; then
    printf 'ASSERTION FAILED: %s\nexpected: %s\nactual:   %s\n' "${message}" "${expected}" "${actual}" >&2
    exit 1
  fi
}

assert_file_exists() {
  local file_path=$1
  local message=$2
  if [[ ! -e "${file_path}" ]]; then
    printf 'ASSERTION FAILED: %s\nmissing: %s\n' "${message}" "${file_path}" >&2
    exit 1
  fi
}

main() {
  local tmp_dir archive_path payload_dir cache_key extract_dir resolved_dir

  tmp_dir="$(mktemp -d)"
  archive_path="${tmp_dir}/sample.tar"
  payload_dir="${tmp_dir}/payload"
  mkdir -p "${payload_dir}/pkg/bin"

  cat > "${payload_dir}/pkg/bin/run" <<'EOF'
#!/usr/bin/env bash
echo ready
EOF
  chmod 0755 "${payload_dir}/pkg/bin/run"

  tar -cf "${archive_path}" -C "${payload_dir}" .

  export APP_CACHE_DIR="${tmp_dir}/cache"
  export APP_ARCHIVE_ENTRYPOINT="pkg/bin/run"
  export APP_ARCHIVE_FORMAT="tar"
  export APP_ARCHIVE_STRIP_COMPONENTS=0

  mkdir -p "${APP_CACHE_DIR}"
  cache_key="$(printf '%s' "${archive_path}:${APP_ARCHIVE_ENTRYPOINT}:${APP_ARCHIVE_STRIP_COMPONENTS}" | sha256sum | awk '{print $1}')"
  extract_dir="${APP_CACHE_DIR}/extract-${cache_key}"
  mkdir -p "${extract_dir}"
  touch "${extract_dir}/stale.marker"

  resolved_dir="$(prepare_archive "${archive_path}")"

  assert_eq "${resolved_dir}" "${extract_dir}" "prepare_archive should reuse the derived cache dir"
  assert_file_exists "${extract_dir}/pkg/bin/run" "prepare_archive should re-extract the missing entrypoint"
  if [[ ! -x "${extract_dir}/pkg/bin/run" ]]; then
    printf 'ASSERTION FAILED: re-extracted entrypoint should be executable\n' >&2
    exit 1
  fi
  if [[ -e "${extract_dir}/stale.marker" ]]; then
    printf 'ASSERTION FAILED: stale cache contents should be discarded\n' >&2
    exit 1
  fi
}

main "$@"
