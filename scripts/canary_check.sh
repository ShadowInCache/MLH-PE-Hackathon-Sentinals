#!/usr/bin/env sh
set -eu

CANARY_BASE_URL="${CANARY_BASE_URL:-http://nginx}"
CANARY_INTERVAL_SECONDS="${CANARY_INTERVAL_SECONDS:-60}"
CANARY_STATE_FILE="${CANARY_STATE_FILE:-/var/lib/ghostlink-security/canary_state.env}"
CANARY_LOG_FILE="${CANARY_LOG_FILE:-/var/lib/ghostlink-security/canary_failures.log}"
CANARY_CODES="health-demo promo-demo checkout-demo dashboard-demo support-demo"

mkdir -p "$(dirname "${CANARY_STATE_FILE}")" "$(dirname "${CANARY_LOG_FILE}")"
touch "${CANARY_STATE_FILE}" "${CANARY_LOG_FILE}"

if [ -f "${CANARY_STATE_FILE}" ]; then
  # shellcheck disable=SC1090
  . "${CANARY_STATE_FILE}"
fi

: "${CANARY_SUCCESS_TOTAL:=0}"
: "${CANARY_FAILURE_TOTAL:=0}"

code_var() {
  echo "$1" | tr '[:lower:]-' '[:upper:]_'
}

probe_url() {
  python - "$1" <<'PY'
import sys
import time
import urllib.error
import urllib.request

url = sys.argv[1]
start = time.time()
status = 0

try:
    request = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(request, timeout=8) as response:
        status = response.getcode() or 0
except urllib.error.HTTPError as exc:
    status = exc.code
except Exception:
    status = 0

latency = max(time.time() - start, 0.0)
print(f"{status} {latency:.6f}")
PY
}

while true; do
  NOW_EPOCH="$(date +%s)"

  for CODE in ${CANARY_CODES}; do
    URL="${CANARY_BASE_URL}/${CODE}"
    PROBE_RESULT="$(probe_url "${URL}")"
    STATUS="$(echo "${PROBE_RESULT}" | awk '{print $1}')"
    LATENCY="$(echo "${PROBE_RESULT}" | awk '{print $2}')"

    VAR_NAME="$(code_var "${CODE}")"
    eval "CANARY_${VAR_NAME}_STATUS='${STATUS}'"
    eval "CANARY_${VAR_NAME}_LATENCY='${LATENCY}'"

    if [ "${STATUS}" = "200" ] || [ "${STATUS}" = "302" ]; then
      CANARY_SUCCESS_TOTAL=$((CANARY_SUCCESS_TOTAL + 1))
    else
      CANARY_FAILURE_TOTAL=$((CANARY_FAILURE_TOTAL + 1))
      printf "%s canary=%s status=%s latency=%s\n" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "${CODE}" "${STATUS}" "${LATENCY}" >> "${CANARY_LOG_FILE}"
    fi
  done

  TMP_FILE="${CANARY_STATE_FILE}.tmp"
  {
    echo "CANARY_SUCCESS_TOTAL=${CANARY_SUCCESS_TOTAL}"
    echo "CANARY_FAILURE_TOTAL=${CANARY_FAILURE_TOTAL}"
    echo "CANARY_LAST_RUN_EPOCH=${NOW_EPOCH}"

    for CODE in ${CANARY_CODES}; do
      VAR_NAME="$(code_var "${CODE}")"
      eval "STATUS=\${CANARY_${VAR_NAME}_STATUS:-0}"
      eval "LATENCY=\${CANARY_${VAR_NAME}_LATENCY:-0}"
      echo "CANARY_${VAR_NAME}_STATUS=${STATUS}"
      echo "CANARY_${VAR_NAME}_LATENCY=${LATENCY}"
    done
  } > "${TMP_FILE}"

  mv "${TMP_FILE}" "${CANARY_STATE_FILE}"
  sleep "${CANARY_INTERVAL_SECONDS}"
done
