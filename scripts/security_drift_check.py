#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import List, Tuple


REQUIRED_SERVICES = [
    "nginx",
    "app1",
    "app2",
    "redis",
    "postgres",
    "alertmanager",
    "canary-runner",
    "security-exporter",
    "prometheus",
    "grafana",
]

REQUIRED_FLAGS = [
    "ENABLE_QUARANTINE_MODE",
    "ENABLE_RISK_SCORING",
    "ENABLE_GHOST_PROBE_ALERTS",
    "ENABLE_CANARY_MONITORING",
    "ENABLE_AUTO_BLOCKING",
    "ENABLE_THREAT_HEATMAP",
]


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


def find_service_block(compose_text: str, service: str) -> str:
    pattern = rf"(?ms)^  {re.escape(service)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)"
    match = re.search(pattern, compose_text)
    return match.group(1) if match else ""


def has_line(text: str, pattern: str) -> bool:
    return re.search(pattern, text, flags=re.MULTILINE) is not None


def check_compose_version(compose_text: str, critical: List[str], fixes: List[str]) -> None:
    if not has_line(compose_text, r'^version:\s*["\']?3\.9["\']?\s*$'):
        critical.append("docker-compose.yml is missing required version: 3.9")
        fixes.append("Set compose top-level version to 3.9")


def check_required_services(compose_text: str, critical: List[str], fixes: List[str]) -> None:
    for service in REQUIRED_SERVICES:
        if not has_line(compose_text, rf"^  {re.escape(service)}:\s*$"):
            critical.append(f"Missing required service '{service}' in docker-compose.yml")
            fixes.append(f"Add '{service}' service definition to docker-compose.yml")


def check_service_runtime_guards(compose_text: str, critical: List[str], fixes: List[str]) -> None:
    for service in ("app1", "app2"):
        block = find_service_block(compose_text, service)
        if not block:
            continue

        if "restart: always" not in block:
            critical.append(f"{service} is missing restart: always")
            fixes.append(f"Add restart: always to {service}")

        if "healthcheck:" not in block:
            critical.append(f"{service} is missing healthcheck configuration")
            fixes.append(f"Add healthcheck to {service}")

        if not has_line(block, r"^\s{6}APP_VERSION:\s*"):
            critical.append(f"{service} is missing APP_VERSION environment variable")
            fixes.append(f"Add APP_VERSION under {service}.environment")

        for flag in REQUIRED_FLAGS:
            if not has_line(block, rf"^\s{{6}}{re.escape(flag)}:\s*"):
                critical.append(f"{service} is missing {flag} environment variable")
                fixes.append(f"Add {flag} under {service}.environment")


def check_nginx_rate_limiting(nginx_text: str, critical: List[str], fixes: List[str]) -> None:
    if "limit_req_zone" not in nginx_text or "limit_req " not in nginx_text:
        critical.append("nginx rate limiting is not configured")
        fixes.append("Add limit_req_zone and limit_req directives to nginx.conf")


def check_prometheus_targets(prom_text: str, critical: List[str], fixes: List[str]) -> None:
    required_targets = ["app1:5000", "app2:5000", "security-exporter:9101", "prometheus:9090"]
    for target in required_targets:
        if target not in prom_text:
            critical.append(f"Prometheus target '{target}' is missing")
            fixes.append(f"Add '{target}' to prometheus scrape_configs")


def check_alertmanager_route(alert_text: str, critical: List[str], fixes: List[str]) -> None:
    if not has_line(alert_text, r"^route:\s*$"):
        critical.append("Alertmanager route block is missing")
        fixes.append("Add top-level route section to alertmanager.yml")


def check_grafana_datasource(datasource_text: str, critical: List[str], fixes: List[str]) -> None:
    if "type: prometheus" not in datasource_text or "uid: prometheus" not in datasource_text:
        critical.append("Grafana Prometheus datasource is missing or misconfigured")
        fixes.append("Ensure grafana/provisioning/datasources/prometheus.yml defines uid: prometheus")


def check_storage_dependencies(compose_text: str, critical: List[str], fixes: List[str]) -> None:
    for dependency in ("redis", "postgres"):
        if not has_line(compose_text, rf"^  {dependency}:\s*$"):
            critical.append(f"{dependency} service is missing in docker-compose.yml")
            fixes.append(f"Add {dependency} service in docker-compose.yml")


def dedupe(items: List[str]) -> List[str]:
    seen = set()
    ordered = []
    for item in items:
        if item not in seen:
            ordered.append(item)
            seen.add(item)
    return ordered


def run_checks(root_dir: Path) -> Tuple[str, List[str], List[str], List[str]]:
    compose_path = root_dir / "docker-compose.yml"
    nginx_path = root_dir / "nginx" / "nginx.conf"
    prometheus_path = root_dir / "prometheus" / "prometheus.yml"
    alertmanager_path = root_dir / "alertmanager" / "alertmanager.yml"
    grafana_ds_path = root_dir / "grafana" / "provisioning" / "datasources" / "prometheus.yml"
    grafana_dash_provider_path = root_dir / "grafana" / "provisioning" / "dashboards" / "dashboard.yml"

    compose_text = read_text(compose_path)
    nginx_text = read_text(nginx_path)
    prom_text = read_text(prometheus_path)
    alert_text = read_text(alertmanager_path)
    datasource_text = read_text(grafana_ds_path)
    dash_provider_text = read_text(grafana_dash_provider_path)

    critical: List[str] = []
    warnings: List[str] = []
    fixes: List[str] = []

    if not compose_text:
        critical.append("docker-compose.yml could not be read")
        fixes.append("Ensure docker-compose.yml exists and is readable")
        return "FAIL", critical, warnings, fixes

    check_compose_version(compose_text, critical, fixes)
    check_required_services(compose_text, critical, fixes)
    check_service_runtime_guards(compose_text, critical, fixes)
    check_storage_dependencies(compose_text, critical, fixes)

    if not nginx_text:
        critical.append("nginx/nginx.conf could not be read")
        fixes.append("Ensure nginx/nginx.conf exists and is readable")
    else:
        check_nginx_rate_limiting(nginx_text, critical, fixes)

    if not prom_text:
        critical.append("prometheus/prometheus.yml could not be read")
        fixes.append("Ensure prometheus/prometheus.yml exists and is readable")
    else:
        check_prometheus_targets(prom_text, critical, fixes)

    if not alert_text:
        critical.append("alertmanager/alertmanager.yml could not be read")
        fixes.append("Ensure alertmanager/alertmanager.yml exists and is readable")
    else:
        check_alertmanager_route(alert_text, critical, fixes)

    if not datasource_text:
        critical.append("Grafana datasource provisioning file is missing")
        fixes.append("Restore grafana/provisioning/datasources/prometheus.yml")
    else:
        check_grafana_datasource(datasource_text, critical, fixes)

    if not dash_provider_text:
        warnings.append("Grafana dashboard provider file could not be read")
        fixes.append("Verify grafana/provisioning/dashboards/dashboard.yml exists")

    critical = dedupe(critical)
    warnings = dedupe(warnings)
    fixes = dedupe(fixes)

    status = "PASS" if not critical else "FAIL"
    return status, critical, warnings, fixes


def print_report(status: str, critical: List[str], warnings: List[str], fixes: List[str]) -> None:
    print(status)
    print()

    print("Critical Issues:")
    if critical:
        for issue in critical:
            print(f"- {issue}")
    else:
        print("- None")
    print()

    print("Warnings:")
    if warnings:
        for warning in warnings:
            print(f"- {warning}")
    else:
        print("- None")
    print()

    print("Suggested Fixes:")
    if fixes:
        for fix in fixes:
            print(f"- {fix}")
    else:
        print("- None")


def main() -> int:
    root_dir = Path(__file__).resolve().parents[1]
    status, critical, warnings, fixes = run_checks(root_dir)
    print_report(status, critical, warnings, fixes)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
