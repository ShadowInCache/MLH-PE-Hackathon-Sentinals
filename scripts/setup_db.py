"""
Quick database setup script for GhostLink.
Creates all tables in the database.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

load_dotenv()

from app.database import db
from app.models import Event, HealthCheck, RequestFingerprint, RiskScore, Url, User
from peewee import PostgresqlDatabase


def main():
    print("=== GhostLink Database Setup ===")

    db_config = {
        "database": os.environ.get("DATABASE_NAME", "hackathon_db"),
        "host": os.environ.get("DATABASE_HOST", "localhost"),
        "port": int(os.environ.get("DATABASE_PORT", 5432)),
        "user": os.environ.get("DATABASE_USER", "postgres"),
        "password": os.environ.get("DATABASE_PASSWORD", "postgres"),
    }

    database = PostgresqlDatabase(**db_config)
    db.initialize(database)

    print(f"Connected to database: {db_config['database']} at {db_config['host']}:{db_config['port']}")

    print("Creating tables...")
    db.create_tables([Url, User, Event, HealthCheck, RiskScore, RequestFingerprint], safe=True)
    print("✅ Tables created successfully!")

    print("\nTables:")
    print("  - urls")
    print("  - users")
    print("  - events")
    print("  - health_checks")
    print("  - risk_scores")
    print("  - request_fingerprints")

    print("\n=== Setup complete! ===")
    print("\nNext steps:")
    print("  1. Run seed script: python scripts/seed.py")
    print("  2. Start server: uv run run.py")
    print("  3. Test health: curl http://localhost:5000/health")


if __name__ == "__main__":
    main()
