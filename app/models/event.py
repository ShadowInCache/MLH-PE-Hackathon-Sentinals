from peewee import CharField, DateTimeField, IntegerField

from app.database import BaseModel
from app.utils import utc_now_naive


class Event(BaseModel):
    url_id = IntegerField(index=True)
    user_id = IntegerField(null=True, index=True)
    event_type = CharField(max_length=50, index=True)
    timestamp = DateTimeField(default=utc_now_naive, index=True)

    class Meta:
        table_name = "events"
        indexes = (
            (("url_id", "timestamp"), False),
            (("user_id", "timestamp"), False),
        )
