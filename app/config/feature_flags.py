import os

_TRUE_VALUES = {"1", "true", "yes", "on"}


def _env_bool(name, default):
    raw_value = os.environ.get(name)
    if raw_value is None:
        return default
    return str(raw_value).strip().lower() in _TRUE_VALUES


ENABLE_QUARANTINE_MODE = _env_bool("ENABLE_QUARANTINE_MODE", True)
ENABLE_RISK_SCORING = _env_bool("ENABLE_RISK_SCORING", True)
ENABLE_GHOST_PROBE_ALERTS = _env_bool("ENABLE_GHOST_PROBE_ALERTS", True)
ENABLE_CANARY_MONITORING = _env_bool("ENABLE_CANARY_MONITORING", True)
ENABLE_AUTO_BLOCKING = _env_bool("ENABLE_AUTO_BLOCKING", False)
ENABLE_THREAT_HEATMAP = _env_bool("ENABLE_THREAT_HEATMAP", False)

FEATURE_FLAGS = {
    "ENABLE_QUARANTINE_MODE": ENABLE_QUARANTINE_MODE,
    "ENABLE_RISK_SCORING": ENABLE_RISK_SCORING,
    "ENABLE_GHOST_PROBE_ALERTS": ENABLE_GHOST_PROBE_ALERTS,
    "ENABLE_CANARY_MONITORING": ENABLE_CANARY_MONITORING,
    "ENABLE_AUTO_BLOCKING": ENABLE_AUTO_BLOCKING,
    "ENABLE_THREAT_HEATMAP": ENABLE_THREAT_HEATMAP,
}


def get_feature_flags():
    return dict(FEATURE_FLAGS)


def is_feature_enabled(flag_name):
    return FEATURE_FLAGS.get(flag_name, False)
