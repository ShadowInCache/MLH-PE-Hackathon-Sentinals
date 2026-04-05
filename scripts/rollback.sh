#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"
ROLLBACK_LOG="${ROOT_DIR}/security/rollback_events.log"
ROLLBACK_STATE_FILE="${ROOT_DIR}/security/rollback_state.env"

usage() {
  cat <<'EOF' >&2
Usage:
  ./scripts/rollback.sh [--dry-run] <app1|app2|all> [target_version]

Examples:
  ./scripts/rollback.sh --dry-run app2
  ./scripts/rollback.sh app2
  ./scripts/rollback.sh app2 v1
  ./scripts/rollback.sh all
EOF
  exit 1
}

DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=true
  shift
fi

if [[ $# -lt 1 ]]; then
  usage
fi

SERVICE_INPUT="$1"
TARGET_VERSION_INPUT="${2:-}"

if [[ "${SERVICE_INPUT}" != "app1" && "${SERVICE_INPUT}" != "app2" && "${SERVICE_INPUT}" != "all" ]]; then
  usage
fi

mkdir -p "$(dirname "${ROLLBACK_LOG}")"
touch "${ROLLBACK_LOG}" "${ROLLBACK_STATE_FILE}"

get_env_value() {
  local service="$1"
  local key="$2"
  awk -v svc="${service}" -v cfg_key="${key}" '
    $0 ~ "^  "svc":" {in_service=1; next}
    in_service && $0 ~ "^  [A-Za-z0-9_-]+:" {in_service=0}
    in_service && $0 ~ "^[[:space:]]{6}"cfg_key":" {
      line=$0
      sub("^[[:space:]]{6}"cfg_key":[[:space:]]*", "", line)
      gsub(/"/, "", line)
      gsub(/\r/, "", line)
      print line
      exit
    }
  ' "${COMPOSE_FILE}"
}

get_env_line_number() {
  local service="$1"
  local key="$2"
  awk -v svc="${service}" -v cfg_key="${key}" '
    $0 ~ "^  "svc":" {in_service=1; next}
    in_service && $0 ~ "^  [A-Za-z0-9_-]+:" {in_service=0}
    in_service && $0 ~ "^[[:space:]]{6}"cfg_key":" {
      print NR
      exit
    }
  ' "${COMPOSE_FILE}"
}

set_env_value() {
  local service="$1"
  local key="$2"
  local new_value="$3"
  local tmp_file
  tmp_file="${COMPOSE_FILE}.tmp"

  awk -v svc="${service}" -v cfg_key="${key}" -v cfg_value="${new_value}" '
    $0 ~ "^  "svc":" {in_service=1}
    in_service && $0 ~ "^  [A-Za-z0-9_-]+:" && $0 !~ "^  "svc":" {in_service=0}
    in_service && $0 ~ "^[[:space:]]{6}"cfg_key":" {
      print "      "cfg_key": \""cfg_value"\""
      next
    }
    {print}
  ' "${COMPOSE_FILE}" > "${tmp_file}"

  mv "${tmp_file}" "${COMPOSE_FILE}"
}

print_compose_change() {
  local service="$1"
  local key="$2"
  local old_value="$3"
  local new_value="$4"
  local line_num
  line_num="$(get_env_line_number "${service}" "${key}")"
  echo "${COMPOSE_FILE}:${line_num} ${service}.${key}: \"${old_value}\" -> \"${new_value}\""
}

get_state_value() {
  local key="$1"
  local default_value="$2"
  local value
  value="$(grep -E "^${key}=" "${ROLLBACK_STATE_FILE}" 2>/dev/null | tail -n 1 | cut -d'=' -f2- || true)"
  value="${value//$'\r'/}"
  if [[ -z "${value}" ]]; then
    echo "${default_value}"
  else
    echo "${value}"
  fi
}

compute_running_mean() {
  local previous_mean="$1"
  local count="$2"
  local latest_value="$3"
  awk -v prev="${previous_mean}" -v n="${count}" -v latest="${latest_value}" 'BEGIN {
    if (n <= 1) {
      printf "%.2f", latest
    } else {
      printf "%.2f", ((prev * (n - 1)) + latest) / n
    }
  }'
}

wait_for_healthy() {
  local service="$1"
  local container_id
  container_id="$(docker compose ps -q "${service}")"

  if [[ -z "${container_id}" ]]; then
    return 1
  fi

  for _ in $(seq 1 30); do
    local status
    status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${container_id}" 2>/dev/null || echo unknown)"
    if [[ "${status}" == "healthy" || "${status}" == "running" ]]; then
      return 0
    fi
    sleep 2
  done

  return 1
}

record_rollback_state() {
  local service="$1"
  local from_version="$2"
  local to_version="$3"
  local recover_minutes="$4"

  local now_utc
  now_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  local detect_minutes
  detect_minutes="${ROLLBACK_DETECT_MINUTES:-2}"

  local rollbacks_total
  local attempts_total
  local success_total
  local prev_mttd
  local prev_mttr

  rollbacks_total="$(get_state_value "ROLLBACKS_TOTAL" "0")"
  attempts_total="$(get_state_value "RECOVERY_ATTEMPTS_TOTAL" "0")"
  success_total="$(get_state_value "RECOVERY_SUCCESS_TOTAL" "0")"
  prev_mttd="$(get_state_value "MEAN_TIME_TO_DETECT_MINUTES" "0")"
  prev_mttr="$(get_state_value "MEAN_TIME_TO_RECOVER_MINUTES" "0")"

  rollbacks_total="$((rollbacks_total + 1))"
  attempts_total="$((attempts_total + 1))"
  success_total="$((success_total + 1))"

  local new_mttd
  local new_mttr
  new_mttd="$(compute_running_mean "${prev_mttd}" "${attempts_total}" "${detect_minutes}")"
  new_mttr="$(compute_running_mean "${prev_mttr}" "${attempts_total}" "${recover_minutes}")"

  cat > "${ROLLBACK_STATE_FILE}" <<EOF
ROLLBACKS_TOTAL=${rollbacks_total}
MEAN_TIME_TO_DETECT_MINUTES=${new_mttd}
MEAN_TIME_TO_RECOVER_MINUTES=${new_mttr}
RECOVERY_ATTEMPTS_TOTAL=${attempts_total}
RECOVERY_SUCCESS_TOTAL=${success_total}
LAST_ROLLBACK_SERVICE=${service}
LAST_ROLLBACK_FROM=${from_version}
LAST_ROLLBACK_TO=${to_version}
LAST_ROLLBACK_AT=${now_utc}
EOF

  printf '%s action=rollback service=%s from=%s to=%s actor=%s status=success\n' \
    "${now_utc}" "${service}" "${from_version}" "${to_version}" "${USER:-unknown}" >> "${ROLLBACK_LOG}"
}

print_state_change_preview() {
  local service="$1"
  local from_version="$2"
  local to_version="$3"

  local detect_minutes
  local rollbacks_total
  local attempts_total
  local success_total
  local prev_mttd
  local prev_mttr

  detect_minutes="${ROLLBACK_DETECT_MINUTES:-2}"
  rollbacks_total="$(get_state_value "ROLLBACKS_TOTAL" "0")"
  attempts_total="$(get_state_value "RECOVERY_ATTEMPTS_TOTAL" "0")"
  success_total="$(get_state_value "RECOVERY_SUCCESS_TOTAL" "0")"
  prev_mttd="$(get_state_value "MEAN_TIME_TO_DETECT_MINUTES" "0")"
  prev_mttr="$(get_state_value "MEAN_TIME_TO_RECOVER_MINUTES" "0")"

  local next_rollbacks_total
  local next_attempts_total
  local next_success_total
  local next_mttd
  local next_mttr

  next_rollbacks_total="$((rollbacks_total + 1))"
  next_attempts_total="$((attempts_total + 1))"
  next_success_total="$((success_total + 1))"
  next_mttd="$(compute_running_mean "${prev_mttd}" "${next_attempts_total}" "${detect_minutes}")"
  next_mttr="$(compute_running_mean "${prev_mttr}" "${next_attempts_total}" "0")"

  echo "${ROLLBACK_STATE_FILE}:ROLLBACKS_TOTAL ${rollbacks_total} -> ${next_rollbacks_total}"
  echo "${ROLLBACK_STATE_FILE}:RECOVERY_ATTEMPTS_TOTAL ${attempts_total} -> ${next_attempts_total}"
  echo "${ROLLBACK_STATE_FILE}:RECOVERY_SUCCESS_TOTAL ${success_total} -> ${next_success_total}"
  echo "${ROLLBACK_STATE_FILE}:MEAN_TIME_TO_DETECT_MINUTES ${prev_mttd} -> ${next_mttd}"
  echo "${ROLLBACK_STATE_FILE}:MEAN_TIME_TO_RECOVER_MINUTES ${prev_mttr} -> ${next_mttr}"
  echo "${ROLLBACK_STATE_FILE}:LAST_ROLLBACK_SERVICE <updated> -> ${service}"
  echo "${ROLLBACK_STATE_FILE}:LAST_ROLLBACK_FROM <updated> -> ${from_version}"
  echo "${ROLLBACK_STATE_FILE}:LAST_ROLLBACK_TO <updated> -> ${to_version}"
  echo "${ROLLBACK_STATE_FILE}:LAST_ROLLBACK_AT <updated> -> <current UTC timestamp at execution>"
}

rollback_service() {
  local service="$1"
  local explicit_target="$2"

  local current_version
  local previous_version
  local target_version

  current_version="$(get_env_value "${service}" "APP_VERSION")"
  previous_version="$(get_env_value "${service}" "PREVIOUS_APP_VERSION")"

  if [[ -n "${explicit_target}" ]]; then
    target_version="${explicit_target}"
  elif [[ -n "${previous_version}" ]]; then
    target_version="${previous_version}"
  elif [[ "${current_version}" == "v2" ]]; then
    target_version="v1"
  else
    target_version="${current_version}"
  fi

  local rollback_start_epoch
  rollback_start_epoch="$(date +%s)"

  if [[ "${DRY_RUN}" == "true" ]]; then
    print_compose_change "${service}" "APP_VERSION" "${current_version}" "${target_version}"
    print_compose_change "${service}" "PREVIOUS_APP_VERSION" "${previous_version}" "${current_version}"
    print_state_change_preview "${service}" "${current_version}" "${target_version}"
    echo "No files changed because --dry-run was used."
    return
  fi

  set_env_value "${service}" "APP_VERSION" "${target_version}"
  set_env_value "${service}" "PREVIOUS_APP_VERSION" "${current_version}"

  docker compose stop "${service}" >/dev/null
  docker compose up -d "${service}" >/dev/null

  if ! wait_for_healthy "${service}"; then
    echo "Rollback failed: ${service} did not become healthy in time" >&2
    exit 1
  fi

  local rollback_end_epoch
  local rollback_minutes
  rollback_end_epoch="$(date +%s)"
  rollback_minutes="$(awk -v s="${rollback_start_epoch}" -v e="${rollback_end_epoch}" 'BEGIN {printf "%.2f", (e-s)/60}')"

  record_rollback_state "${service}" "${current_version}" "${target_version}" "${rollback_minutes}"
  echo "Rollback complete for ${service}: ${current_version} -> ${target_version}"
}

if [[ "${SERVICE_INPUT}" == "all" ]]; then
  rollback_service "app2" "${TARGET_VERSION_INPUT}"
  rollback_service "app1" "${TARGET_VERSION_INPUT}"
else
  rollback_service "${SERVICE_INPUT}" "${TARGET_VERSION_INPUT}"
fi
