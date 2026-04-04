#!/usr/bin/env python3
"""
Idempotent seed script to load CSV data into GhostLink database.
Safe to run multiple times - uses upsert logic to avoid duplicates.
"""
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

load_dotenv()

from app.database import db
from app.models import Event, HealthCheck, RequestFingerprint, RiskScore, Url, User
from app.utils import utc_now_naive


def load_users_csv(filepath):
    """Load users from CSV file."""
    if not os.path.exists(filepath):
        print(f"Warning: {filepath} not found, skipping users")
        return

    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        count = 0
        for row in reader:
            user, created = User.get_or_create(
                id=int(row["id"]),
                defaults={
                    "username": row["username"],
                    "email": row["email"],
                    "created_at": row.get("created_at", utc_now_naive()),
                },
            )
            if created:
                count += 1

    print(f"Loaded {count} new users")


def load_urls_csv(filepath):
    """Load URLs from CSV file."""
    if not os.path.exists(filepath):
        print(f"Warning: {filepath} not found, skipping URLs")
        return

    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        count = 0
        for row in reader:
            user_id = row.get("user_id")
            if user_id:
                user_id = int(user_id) if user_id.strip() else None

            url, created = Url.get_or_create(
                id=int(row["id"]),
                defaults={
                    "user_id": user_id,
                    "short_code": row["short_code"],
                    "original_url": row["original_url"],
                    "title": row.get("title"),
                    "is_active": row.get("is_active", "1") == "1",
                    "created_at": row.get("created_at", utc_now_naive()),
                    "updated_at": row.get("updated_at", utc_now_naive()),
                },
            )
            if created:
                count += 1

    print(f"Loaded {count} new URLs")


def load_events_csv(filepath):
    """Load events from CSV file."""
    if not os.path.exists(filepath):
        print(f"Warning: {filepath} not found, skipping events")
        return

    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        count = 0
        for row in reader:
            user_id = row.get("user_id")
            if user_id:
                user_id = int(user_id) if user_id.strip() else None

            event, created = Event.get_or_create(
                id=int(row["id"]),
                defaults={
                    "url_id": int(row["url_id"]),
                    "user_id": user_id,
                    "event_type": row["event_type"],
                    "timestamp": row.get("timestamp", utc_now_naive()),
                },
            )
            if created:
                count += 1

    print(f"Loaded {count} new events")


def main():
    """Main seed script entry point."""
    print("=== GhostLink Database Seed Script ===")

    db_config = {
        "database": os.environ.get("DATABASE_NAME", "hackathon_db"),
        "host": os.environ.get("DATABASE_HOST", "localhost"),
        "port": int(os.environ.get("DATABASE_PORT", 5432)),
        "user": os.environ.get("DATABASE_USER", "postgres"),
        "password": os.environ.get("DATABASE_PASSWORD", "postgres"),
    }

    from peewee import PostgresqlDatabase

    database = PostgresqlDatabase(**db_config)
    db.initialize(database)

    print(f"Connected to database: {db_config['database']}")

    with db.atomic():
        db.create_tables(
            [Url, User, Event, HealthCheck, RiskScore, RequestFingerprint], safe=True
        )
        print("Tables created (if not exists)")

    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    if not os.path.exists(data_dir):
        data_dir = "."

    load_users_csv(os.path.join(data_dir, "users.csv"))
    load_urls_csv(os.path.join(data_dir, "urls.csv"))
    load_events_csv(os.path.join(data_dir, "events.csv"))

    print("\n=== Seed complete! ===")


if __name__ == "__main__":
    main()
