FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Build dependencies are required for PostgreSQL client libraries.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./

RUN pip install --upgrade pip setuptools wheel \
    && pip install \
        "flask>=3.1" \
        "peewee>=3.17" \
        "psycopg2-binary>=2.9" \
        "python-dotenv>=1.0" \
        "faker>=33.0" \
        "gunicorn>=22.0"

COPY . .

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "30", "run:app"]
