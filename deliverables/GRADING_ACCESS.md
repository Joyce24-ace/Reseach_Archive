# Grading Access (submit with your assignment)

Provide these values to your instructor **after** deploying to Render:

| Field | Value |
|-------|--------|
| **Live URL** | `https://<your-service>.onrender.com` |
| **Admin URL** | `https://<your-service>.onrender.com/admin/` |
| **Username** | Value of `GRADING_SUPERUSER_USERNAME` (default: `grader`) |
| **Password** | Value of `GRADING_SUPERUSER_PASSWORD` (set in Render env — do not commit) |

Create the account on deploy via `python manage.py setup_scholarvault` (runs automatically in `build.sh` when `GRADING_SUPERUSER_PASSWORD` is set).

For local testing:

```bash
set GRADING_SUPERUSER_PASSWORD=YourSecurePassword123!
python manage.py setup_scholarvault
```
