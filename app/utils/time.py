from datetime import UTC, datetime


def utc_now_naive():
    """Return the current UTC timestamp without tzinfo for DB compatibility."""
    return datetime.now(UTC).replace(tzinfo=None)