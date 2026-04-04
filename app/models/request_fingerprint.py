from peewee import (
    BooleanField,
    CharField,
    DateTimeField,
    IntegerField,
)

from app.database import BaseModel
from app.utils import utc_now_naive


class RequestFingerprint(BaseModel):
    short_code = CharField(max_length=64, null=True, index=True)
    client_ip = CharField(max_length=64, null=True, index=True)
    user_agent = CharField(max_length=512, null=True)
    status_code = IntegerField(index=True)
    is_invalid_short_code = BooleanField(default=False, index=True)
    is_ghost_probe = BooleanField(default=False, index=True)
    is_quarantined = BooleanField(default=False, index=True)
    is_dead_link = BooleanField(default=False, index=True)
    created_at = DateTimeField(default=utc_now_naive, index=True)

    class Meta:
        table_name = "request_fingerprints"
        indexes = (
            (("client_ip", "created_at"), False),
            (("short_code", "created_at"), False),
        )
