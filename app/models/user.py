from peewee import CharField, DateTimeField

from app.database import BaseModel
from app.utils import utc_now_naive


class User(BaseModel):
    username = CharField(max_length=100, unique=True, index=True)
    email = CharField(max_length=255, unique=True, index=True)
    created_at = DateTimeField(default=utc_now_naive)

    class Meta:
        table_name = "users"
