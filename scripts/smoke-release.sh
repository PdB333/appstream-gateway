#!/usr/bin/env bash
set -euo pipefail

MANAGER_URL="${MANAGER_URL:-https://app-web.selatincankaraborklu.fr}"
ADMIN_API_TOKEN="${ADMIN_API_TOKEN:-}"
CLIENT_ID_PREFIX="${CLIENT_ID_PREFIX:-release-smoke}"

if [[ -z "${ADMIN_API_TOKEN}" ]]; then
  echo "ADMIN_API_TOKEN is required" >&2
  exit 1
fi

if [[ $# -gt 0 ]]; then
  APP_IDS=("$@")
else
  APP_IDS=(firefox brave xterm)
fi

get_launch_url() {
  local app_id=$1
  local client_id=$2
  local response
  response="$(curl -fsS \
    -H "Authorization: Bearer ${ADMIN_API_TOKEN}" \
    "${MANAGER_URL}/api/apps/${app_id}/launch-link?clientId=${client_id}")"
  python3 -c 'import json,sys; print(json.loads(sys.argv[1])["url"])' "${response}"
}

check_launch() {
  local app_id=$1
  local client_id=$2
  local launch_url status_line status_code

  launch_url="$(get_launch_url "${app_id}" "${client_id}")"
  status_line="$(curl -sS -D - -o /dev/null "${launch_url}")"
  status_code="$(printf '%s\n' "${status_line}" | awk 'NR==1 { print $2 }')"

  if [[ "${status_code}" != "302" ]]; then
    echo "Smoke test failed for ${app_id}: expected 302 from public launch, got ${status_code}" >&2
    exit 1
  fi

  echo "${app_id}: ok"
}

for app_id in "${APP_IDS[@]}"; do
  client_id="${CLIENT_ID_PREFIX}-${app_id}-$(date +%s)"
  check_launch "${app_id}" "${client_id}"
done
