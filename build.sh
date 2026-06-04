#!/usr/bin/env bash
# exit on error
set -o errexit

# Install required dependencies
pip install -r requirements.txt

# Compile static design layouts (Tailwind, admin panels)
python manage.py collectstatic --no-input


# Run database migrations securely on Render's PostgreSQL
python manage.py migrate --no-input
python manage.py setup_scholarvault