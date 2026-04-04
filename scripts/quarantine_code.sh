#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BLOCKED_FILE="${ROOT_DIR}/nginx/blocked_codes.conf"
AUDIT_LOG="${ROOT_DIR}/security/quarantine_actions.log"
SHORT_CODE="${1:-}"

if [[ -z "${SHORT_CODE}" ]]; then
  echo "Usage: ./scripts/quarantine_code.sh <short_code>" >&2
  exit 1
fi

if [[ ! "${SHORT_CODE}" =~ ^[A-Za-z0-9_-]+$ ]]; then
  echo "Invalid short code '${SHORT_CODE}'. Allowed characters: A-Z a-z 0-9 _ -" >&2
  exit 1
fi

mkdir -p "$(dirname "${AUDIT_LOG}")"
touch "${BLOCKED_FILE}" "${AUDIT_LOG}"

RULE_LINE="~^/${SHORT_CODE}$ 1;"
if ! grep -Fqx "${RULE_LINE}" "${BLOCKED_FILE}"; then
  printf "%s\n" "${RULE_LINE}" >> "${BLOCKED_FILE}"
fi

TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
printf "%s action=quarantine short_code=%s actor=%s\n" "${TIMESTAMP}" "${SHORT_CODE}" "${USER:-unknown}" >> "${AUDIT_LOG}"

if docker compose exec -T nginx nginx -s reload >/dev/null 2>&1; then
  echo "Nginx reloaded through docker compose exec."
elif docker kill -s HUP ghostlink-nginx >/dev/null 2>&1; then
  echo "Nginx reloaded through container HUP signal."
else
  echo "Failed to reload nginx container. Ensure the stack is running." >&2
  exit 1
fi

echo "Quarantined short code: ${SHORT_CODE}"
