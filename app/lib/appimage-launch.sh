#!/usr/bin/env bash

appimage_extract_dir() {
  local cache_dir=$1
  local appimage_path=$2
  local appimage_name

  appimage_name="$(basename "${appimage_path}" .AppImage)"
  printf '%s' "${cache_dir}/extracted/${appimage_name}"
}

resolve_appimage_launch_spec() {
  local cache_dir=$1
  local download_dir=$2
  local appimage_path=$3
  local extract_and_run=$4
  local app_args=${5-}
  local requested_workdir=${6-}

  APPIMAGE_RESOLVED_WORKDIR="${requested_workdir}"
  APPIMAGE_RESOLVED_COMMAND="${appimage_path}"
  APPIMAGE_STAGED_PATH="${download_dir}/$(basename "${appimage_path}")"
  APPIMAGE_EXTRACT_DIR="$(appimage_extract_dir "${cache_dir}" "${appimage_path}")"

  if [[ "${extract_and_run}" == "1" ]]; then
    APPIMAGE_RESOLVED_WORKDIR="${APPIMAGE_EXTRACT_DIR}"
    APPIMAGE_RESOLVED_COMMAND="./AppRun"
  fi

  if [[ -n "${app_args}" ]]; then
    APPIMAGE_RESOLVED_COMMAND="${APPIMAGE_RESOLVED_COMMAND} ${app_args}"
  fi
}
