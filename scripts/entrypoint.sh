#!/bin/sh
set -e

VERSIONS_DIR="app/alembic/versions"

# Ensure versions directory exists
mkdir -p "$VERSIONS_DIR"

# Check if there are any migration files
if [ -z "$(ls -A "$VERSIONS_DIR"/*.py 2>/dev/null)" ]; then
    echo "No migrations found. Creating initial migration..."
    alembic revision --autogenerate -m "init"
fi

# Apply migrations
echo "Applying migrations..."
alembic upgrade head

# Start FastAPI
echo "Starting FastAPI..."
exec fastapi dev app/main.py --host 0.0.0.0
