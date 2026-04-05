import os
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class ReleaseInfo:
    version: str
    git_sha: str
    deployed_at: str
    release_owner: str
    release_notes_url: str

    def to_dict(self):
        return asdict(self)


def _env(name, default):
    value = os.environ.get(name)
    if value is None:
        return default
    cleaned = str(value).strip()
    return cleaned or default


def get_release_info():
    return ReleaseInfo(
        version=_env("APP_VERSION", "v1-dev"),
        git_sha=_env("GIT_SHA", "local"),
        deployed_at=_env("DEPLOYED_AT", "unknown"),
        release_owner=_env("RELEASE_OWNER", "platform"),
        release_notes_url=_env("RELEASE_NOTES_URL", ""),
    )


def get_rollback_state_path():
    return Path(
        _env("ROLLBACK_STATE_FILE", "/var/lib/ghostlink-security/rollback_state.env")
    )


def _safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value, default=0):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def get_recovery_state():
    state = {
        "rollbacks_total": 0,
        "mean_time_to_detect_minutes": 0.0,
        "mean_time_to_recover_minutes": 0.0,
        "recovery_attempts_total": 0,
        "recovery_success_total": 0,
    }

    path = get_rollback_state_path()
    if not path.exists() or not path.is_file():
        return state

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return state

    values = {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()

    state["rollbacks_total"] = _safe_int(values.get("ROLLBACKS_TOTAL"), 0)
    state["mean_time_to_detect_minutes"] = _safe_float(
        values.get("MEAN_TIME_TO_DETECT_MINUTES"), 0.0
    )
    state["mean_time_to_recover_minutes"] = _safe_float(
        values.get("MEAN_TIME_TO_RECOVER_MINUTES"), 0.0
    )
    state["recovery_attempts_total"] = _safe_int(
        values.get("RECOVERY_ATTEMPTS_TOTAL"), 0
    )
    state["recovery_success_total"] = _safe_int(
        values.get("RECOVERY_SUCCESS_TOTAL"), 0
    )

    return state
