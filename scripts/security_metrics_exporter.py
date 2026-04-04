#!/usr/bin/env python3
import csv
import json
import os
import re
import time
from collections import Counter, defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

PORT = int(os.getenv("SECURITY_METRICS_PORT", "9101"))
BLOCKED_CODES_PATH = os.getenv("BLOCKED_CODES_PATH", "/etc/ghostlink/blocked_codes.conf")
CANARY_STATE_FILE = os.getenv("CANARY_STATE_FILE", "/var/lib/ghostlink-security/canary_state.env")
NGINX_ACCESS_LOG_PATH = os.getenv("NGINX_ACCESS_LOG_PATH", "/var/log/nginx/access.log")
URLS_CSV_PATH = os.getenv("URLS_CSV_PATH", "/data/urls.csv")
EVENTS_CSV_PATH = os.getenv("EVENTS_CSV_PATH", "/data/events.csv")
MAX_LOG_BYTES = int(os.getenv("SECURITY_LOG_TAIL_BYTES", "4000000"))
MAX_RISK_SCORE_SERIES = int(os.getenv("MAX_RISK_SCORE_SERIES", "250"))

CANARY_CODES = [
    "health-demo",
    "promo-demo",
    "checkout-demo",
    "dashboard-demo",
    "support-demo",
]

SUSPICIOUS_TLDS = {
    "zip",
    "top",
    "click",
    "xyz",
    "gq",
    "tk",
    "ml",
    "work",
    "link",
}

RESERVED_ROUTES = {
    "health",
    "metrics",
    "shorten",
    "urls",
    *CANARY_CODES,
}

SHORT_CODE_RE = re.compile(r"^[A-Za-z0-9_-]+$")
BLOCKED_LINE_RE = re.compile(r"~\^/([A-Za-z0-9_-]+)\$\s+1;")


def escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def to_int(value, default=0):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def to_float(value, default=0.0):
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def load_env_state(path: str):
    state = {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                item = line.strip()
                if not item or item.startswith("#") or "=" not in item:
                    continue
                key, value = item.split("=", 1)
                state[key.strip()] = value.strip()
    except FileNotFoundError:
        pass
    return state


def read_recent_lines(path: str, max_bytes: int):
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            offset = max(size - max_bytes, 0)
            handle.seek(offset, os.SEEK_SET)
            if offset > 0:
                handle.readline()
            data = handle.read()
    except FileNotFoundError:
        return []

    text = data.decode("utf-8", errors="ignore")
    return [line for line in text.splitlines() if line.strip()]


def parse_request_path(request_line: str) -> str:
    if not request_line:
        return ""
    parts = request_line.split(" ")
    if len(parts) < 2:
        return ""
    return urlparse(parts[1]).path


def extract_short_code(path: str) -> str:
    if not path:
        return ""
    code = path.strip("/")
    if not code or "/" in code:
        return ""
    if code in RESERVED_ROUTES:
        return ""
    if not SHORT_CODE_RE.match(code):
        return ""
    return code


def load_quarantined_codes(path: str):
    codes = set()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                blocked_match = BLOCKED_LINE_RE.match(line)
                if blocked_match:
                    codes.add(blocked_match.group(1))
                    continue
                if SHORT_CODE_RE.match(line):
                    codes.add(line)
    except FileNotFoundError:
        pass
    return codes


def parse_nginx_security_signals(path: str):
    request_count_by_ip = Counter()
    invalid_hits_by_ip = Counter()
    ghost_hits_by_ip = Counter()
    blocked_hits_by_ip = Counter()
    dead_hits_by_ua = Counter()
    probed_short_codes = Counter()
    redirect_hits_by_short_code = Counter()

    blocked_requests_total = 0
    invalid_short_code_hits_total = 0

    for line in read_recent_lines(path, MAX_LOG_BYTES):
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue

        ip = str(payload.get("remote_addr") or "unknown")
        ua = str(payload.get("http_user_agent") or "unknown")[:180]
        status = to_int(payload.get("status"), default=0)
        request_line = str(payload.get("request") or "")
        path_value = parse_request_path(request_line)
        short_code = extract_short_code(path_value)

        request_count_by_ip[ip] += 1

        if short_code and status in (404, 410):
            probed_short_codes[short_code] += 1
            ghost_hits_by_ip[ip] += 1
            dead_hits_by_ua[ua] += 1

        if short_code and status in (301, 302, 307, 308):
            redirect_hits_by_short_code[short_code] += 1

        if status == 410:
            blocked_requests_total += 1
            blocked_hits_by_ip[ip] += 1

        if status == 404 and short_code:
            invalid_short_code_hits_total += 1
            invalid_hits_by_ip[ip] += 1

    suspicious_ip_score = {}
    for ip, total_requests in request_count_by_ip.items():
        score = 0
        if invalid_hits_by_ip[ip] >= 20:
            score += 40
        if ghost_hits_by_ip[ip] >= 30:
            score += 25
        if total_requests >= 300:
            score += 20
        if blocked_hits_by_ip[ip] >= 10:
            score += 15
        if score > 0:
            suspicious_ip_score[ip] = float(min(score, 100))

    suspicious_clients_total = len(suspicious_ip_score)
    repeated_user_agent_hits_total = sum(count for count in dead_hits_by_ua.values() if count >= 25)

    top_ip_score = dict(sorted(suspicious_ip_score.items(), key=lambda item: item[1], reverse=True)[:10])
    top_user_agents = dict(sorted(dead_hits_by_ua.items(), key=lambda item: item[1], reverse=True)[:10])
    top_probed_codes = dict(sorted(probed_short_codes.items(), key=lambda item: item[1], reverse=True)[:10])

    return {
        "blocked_requests_total": float(blocked_requests_total),
        "invalid_short_code_hits_total": float(invalid_short_code_hits_total),
        "suspicious_clients_total": float(suspicious_clients_total),
        "repeated_user_agent_hits_total": float(repeated_user_agent_hits_total),
        "probed_short_codes": probed_short_codes,
        "redirect_hits_by_short_code": redirect_hits_by_short_code,
        "top_ip_score": top_ip_score,
        "top_user_agents": top_user_agents,
        "top_probed_codes": top_probed_codes,
    }


def load_repeated_delete_recreate(path: str):
    events = defaultdict(lambda: {"created": 0, "deleted": 0})
    try:
        with open(path, "r", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                url_id = (row.get("url_id") or "").strip()
                event_type = (row.get("event_type") or "").strip().lower()
                if not url_id or event_type not in ("created", "deleted"):
                    continue
                events[url_id][event_type] += 1
    except FileNotFoundError:
        return set()

    churn_ids = set()
    for url_id, counts in events.items():
        if counts["deleted"] >= 2 or (counts["deleted"] >= 1 and counts["created"] >= 2):
            churn_ids.add(url_id)
    return churn_ids


def classify_risk(score: float):
    if score <= 30:
        return "SAFE"
    if score <= 60:
        return "WATCHLIST"
    return "THREAT"


def build_link_risk_scores(urls_path: str, quarantined_codes, probed_short_codes: Counter, churn_ids):
    best_by_code = {}

    try:
        with open(urls_path, "r", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                short_code = (row.get("short_code") or "").strip()
                if not short_code or not SHORT_CODE_RE.match(short_code):
                    continue

                url_id = (row.get("id") or "").strip()
                original_url = (row.get("original_url") or "").strip()
                parsed = urlparse(original_url)
                hostname = (parsed.hostname or "").lower()
                tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""
                path_depth = len([segment for segment in parsed.path.split("/") if segment])
                is_active = (row.get("is_active") or "").strip().lower() == "true"

                score = 0
                if (not is_active) or short_code in quarantined_codes:
                    score += 30
                if path_depth > 3:
                    score += 20
                if probed_short_codes.get(short_code, 0) >= 10:
                    score += 15
                if tld in SUSPICIOUS_TLDS:
                    score += 20
                if url_id in churn_ids:
                    score += 15

                score = float(min(score, 100))
                level = classify_risk(score)

                current = best_by_code.get(short_code)
                if current is None or score > current[0]:
                    best_by_code[short_code] = (score, level)
    except FileNotFoundError:
        pass

    for code in CANARY_CODES:
        if code not in best_by_code:
            best_by_code[code] = (0.0, "SAFE")

    risk_items = [(code, values[0], values[1]) for code, values in best_by_code.items()]

    safe_total = sum(1 for _, _, level in risk_items if level == "SAFE")
    watchlist_total = sum(1 for _, _, level in risk_items if level == "WATCHLIST")
    threat_total = sum(1 for _, _, level in risk_items if level == "THREAT")

    ordered = sorted(risk_items, key=lambda item: (item[1], item[0]), reverse=True)
    selected = ordered[:MAX_RISK_SCORE_SERIES]
    selected_codes = {item[0] for item in selected}

    for code in sorted(quarantined_codes.union(set(CANARY_CODES))):
        if code in best_by_code and code not in selected_codes:
            score, level = best_by_code[code]
            selected.append((code, score, level))
            selected_codes.add(code)

    threat_codes = {code for code, _, level in risk_items if level == "THREAT"}

    return {
        "selected": selected,
        "safe_total": float(safe_total),
        "watchlist_total": float(watchlist_total),
        "threat_total": float(threat_total),
        "threat_codes": threat_codes,
    }


def collect_metrics_snapshot():
    canary_state = load_env_state(CANARY_STATE_FILE)
    quarantined_codes = load_quarantined_codes(BLOCKED_CODES_PATH)
    signals = parse_nginx_security_signals(NGINX_ACCESS_LOG_PATH)
    churn_ids = load_repeated_delete_recreate(EVENTS_CSV_PATH)
    risks = build_link_risk_scores(URLS_CSV_PATH, quarantined_codes, signals["probed_short_codes"], churn_ids)

    affected_codes = set(quarantined_codes).union(risks["threat_codes"])
    affected_redirects_total = float(
        sum(signals["redirect_hits_by_short_code"].get(code, 0) for code in affected_codes)
    )

    return {
        "canary_state": canary_state,
        "quarantined_codes": quarantined_codes,
        "signals": signals,
        "risks": risks,
        "affected_short_codes_total": float(len(affected_codes)),
        "affected_redirects_total": affected_redirects_total,
        "generated_unixtime": float(time.time()),
    }


def render_metrics_text():
    try:
        snapshot = collect_metrics_snapshot()
    except Exception as error:
        return (
            "# HELP ghostlink_security_exporter_up 1 when the security exporter can build metrics\n"
            "# TYPE ghostlink_security_exporter_up gauge\n"
            "ghostlink_security_exporter_up 0\n"
            f"# ghostlink_security_exporter_error {str(error).strip()}\n"
        )

    state = snapshot["canary_state"]
    signals = snapshot["signals"]
    risks = snapshot["risks"]

    success_total = to_float(state.get("CANARY_SUCCESS_TOTAL"), 0)
    failure_total = to_float(state.get("CANARY_FAILURE_TOTAL"), 0)

    lines = [
        "# HELP ghostlink_security_exporter_up 1 when the security exporter can build metrics",
        "# TYPE ghostlink_security_exporter_up gauge",
        "ghostlink_security_exporter_up 1",
        "# HELP ghostlink_security_metrics_generated_unixtime Security metrics generation epoch timestamp",
        "# TYPE ghostlink_security_metrics_generated_unixtime gauge",
        f"ghostlink_security_metrics_generated_unixtime {snapshot['generated_unixtime']:.0f}",
        "# HELP ghostlink_canary_success_total Total successful synthetic canary checks",
        "# TYPE ghostlink_canary_success_total counter",
        f"ghostlink_canary_success_total {success_total:.0f}",
        "# HELP ghostlink_canary_failures_total Total failed synthetic canary checks",
        "# TYPE ghostlink_canary_failures_total counter",
        f"ghostlink_canary_failures_total {failure_total:.0f}",
        "# HELP ghostlink_canary_latency_seconds Latest latency observed for each synthetic canary",
        "# TYPE ghostlink_canary_latency_seconds gauge",
        "# HELP ghostlink_canary_status Latest HTTP status observed for each synthetic canary",
        "# TYPE ghostlink_canary_status gauge",
    ]

    for code in CANARY_CODES:
        env_name = code.upper().replace("-", "_")
        latency = to_float(state.get(f"CANARY_{env_name}_LATENCY"), 0)
        status = to_float(state.get(f"CANARY_{env_name}_STATUS"), 0)
        escaped_code = escape_label(code)
        lines.append(f'ghostlink_canary_latency_seconds{{short_code="{escaped_code}"}} {latency:.6f}')
        lines.append(f'ghostlink_canary_status{{short_code="{escaped_code}"}} {status:.0f}')

    lines.extend(
        [
            "# HELP ghostlink_quarantined_urls_total Current number of quarantined short codes",
            "# TYPE ghostlink_quarantined_urls_total gauge",
            f"ghostlink_quarantined_urls_total {float(len(snapshot['quarantined_codes'])):.0f}",
            "# HELP ghostlink_blocked_requests_total Total blocked requests served with HTTP 410",
            "# TYPE ghostlink_blocked_requests_total counter",
            f"ghostlink_blocked_requests_total {signals['blocked_requests_total']:.0f}",
            "# HELP ghostlink_suspicious_clients_total Number of currently flagged suspicious client IPs",
            "# TYPE ghostlink_suspicious_clients_total gauge",
            f"ghostlink_suspicious_clients_total {signals['suspicious_clients_total']:.0f}",
            "# HELP ghostlink_invalid_short_code_hits_total Total invalid short-code hits observed in Nginx logs",
            "# TYPE ghostlink_invalid_short_code_hits_total counter",
            f"ghostlink_invalid_short_code_hits_total {signals['invalid_short_code_hits_total']:.0f}",
            "# HELP ghostlink_repeated_user_agent_hits_total Total dead-link hits from repeatedly abusive user agents",
            "# TYPE ghostlink_repeated_user_agent_hits_total counter",
            f"ghostlink_repeated_user_agent_hits_total {signals['repeated_user_agent_hits_total']:.0f}",
            "# HELP ghostlink_safe_links_total Count of links currently classified as SAFE",
            "# TYPE ghostlink_safe_links_total gauge",
            f"ghostlink_safe_links_total {risks['safe_total']:.0f}",
            "# HELP ghostlink_watchlist_links_total Count of links currently classified as WATCHLIST",
            "# TYPE ghostlink_watchlist_links_total gauge",
            f"ghostlink_watchlist_links_total {risks['watchlist_total']:.0f}",
            "# HELP ghostlink_threat_links_total Count of links currently classified as THREAT",
            "# TYPE ghostlink_threat_links_total gauge",
            f"ghostlink_threat_links_total {risks['threat_total']:.0f}",
            "# HELP ghostlink_affected_short_codes_total Number of short codes currently estimated as impacted",
            "# TYPE ghostlink_affected_short_codes_total gauge",
            f"ghostlink_affected_short_codes_total {snapshot['affected_short_codes_total']:.0f}",
            "# HELP ghostlink_affected_redirects_total Total redirects observed for affected short codes",
            "# TYPE ghostlink_affected_redirects_total counter",
            f"ghostlink_affected_redirects_total {snapshot['affected_redirects_total']:.0f}",
            "# HELP ghostlink_risk_score Link risk score from 0 to 100",
            "# TYPE ghostlink_risk_score gauge",
        ]
    )

    for code, score, level in risks["selected"]:
        escaped_code = escape_label(code)
        escaped_level = escape_label(level)
        lines.append(
            f'ghostlink_risk_score{{short_code="{escaped_code}",risk_level="{escaped_level}"}} {score:.2f}'
        )

    lines.extend(
        [
            "# HELP ghostlink_suspicious_ip_score Risk score for suspicious client IPs",
            "# TYPE ghostlink_suspicious_ip_score gauge",
        ]
    )

    for ip, score in signals["top_ip_score"].items():
        lines.append(f'ghostlink_suspicious_ip_score{{ip="{escape_label(ip)}"}} {score:.2f}')

    lines.extend(
        [
            "# HELP ghostlink_suspicious_user_agent_hits Dead-link hits observed for suspicious user agents",
            "# TYPE ghostlink_suspicious_user_agent_hits gauge",
        ]
    )

    for user_agent, hits in signals["top_user_agents"].items():
        lines.append(
            f'ghostlink_suspicious_user_agent_hits{{user_agent="{escape_label(user_agent)}"}} {float(hits):.0f}'
        )

    lines.extend(
        [
            "# HELP ghostlink_probed_short_code_hits Most probed short codes observed in Nginx logs",
            "# TYPE ghostlink_probed_short_code_hits gauge",
        ]
    )

    for short_code, hits in signals["top_probed_codes"].items():
        lines.append(f'ghostlink_probed_short_code_hits{{short_code="{escape_label(short_code)}"}} {float(hits):.0f}')

    return "\n".join(lines) + "\n"


class SecurityMetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            body = b'{"status":"ok"}\n'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path.startswith("/metrics"):
            payload = render_metrics_text().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        return


def run_server():
    server = ThreadingHTTPServer(("0.0.0.0", PORT), SecurityMetricsHandler)
    print(f"security metrics exporter listening on 0.0.0.0:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    run_server()
