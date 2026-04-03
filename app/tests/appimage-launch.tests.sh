#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=../lib/appimage-launch.sh
source "${ROOT_DIR}/lib/appimage-launch.sh"

assert_eq() {
  local actual=$1
  local expected=$2
  local message=$3
  if [[ "${actual}" != "${expected}" ]]; then
    printf 'ASSERTION FAILED: %s\nexpected: %s\nactual:   %s\n' "${message}" "${expected}" "${actual}" >&2
    exit 1
  fi
}

main() {
  local cache_dir="/persist/cache"
  local download_dir="/ephemeral/downloads"
  local appimage_path="${cache_dir}/abc-Lens.AppImage"
  local extract_dir
  local workdir
  local command

  extract_dir="$(appimage_extract_dir "${cache_dir}" "${appimage_path}")"
  assert_eq "${extract_dir}" "/persist/cache/extracted/abc-Lens" "extract dir should stay in persistent cache"

  resolve_appimage_launch_spec \
    "${cache_dir}" \
    "${download_dir}" \
    "${appimage_path}" \
    "1" \
    "--flag --second" \
    ""

  workdir="${APPIMAGE_RESOLVED_WORKDIR}"
  command="${APPIMAGE_RESOLVED_COMMAND}"

  assert_eq "${workdir}" "/persist/cache/extracted/abc-Lens" "pre-extracted AppImage should launch from extracted dir"
  assert_eq "${command}" "./AppRun --flag --second" "pre-extracted AppImage should use relative AppRun command"
}

main "$@"
