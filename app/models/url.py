from peewee import BooleanField, CharField, DateTimeField, ForeignKeyField, IntegerField

from app.database import BaseModel
from app.utils import utc_now_naive


class Url(BaseModel):
    user_id = IntegerField(null=True, index=True)
    short_code = CharField(max_length=10, unique=True, index=True)
    original_url = CharField(max_length=2048)
    title = CharField(max_length=255, null=True)
    is_active = BooleanField(default=True, index=True)
    created_at = DateTimeField(default=utc_now_naive)
    updated_at = DateTimeField(default=utc_now_naive)

    class Meta:
        table_name = "urls"
        indexes = (
            (("user_id", "is_active"), False),
            (("created_at",), False),
        )

    def save(self, *args, **kwargs):
        self.updated_at = utc_now_naive()
        return super().save(*args, **kwargs)
