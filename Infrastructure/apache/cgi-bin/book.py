#!/usr/bin/env python3
"""
book.py — Waystar Connect booking endpoint.

Accepts a JSON POST from the public-facing site, validates the payload,
and inserts a row into the `appointments` table on db-internal.

Credentials are loaded from /etc/waystar/db.env (KEY=VALUE per line).
"""

import json
import os
import re
import sys
from datetime import date, datetime

import psycopg2

CREDS_PATH = "/etc/waystar/db.env"
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
TIME_RE = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]$")
FOCUS_MAX = 80
NOTES_MAX = 2000
NAME_MAX = 120
EMAIL_MAX = 160


def respond(status, body):
    payload = json.dumps(body)
    sys.stdout.write(f"Status: {status}\r\n")
    sys.stdout.write("Content-Type: application/json; charset=utf-8\r\n")
    sys.stdout.write("Cache-Control: no-store\r\n")
    sys.stdout.write(f"Content-Length: {len(payload.encode('utf-8'))}\r\n")
    sys.stdout.write("\r\n")
    sys.stdout.write(payload)
    sys.stdout.flush()
    sys.exit(0)


def load_db_env():
    env = {}
    with open(CREDS_PATH, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def validate(payload):
    errors = {}

    name = (payload.get("name") or "").strip()
    if not name:
        errors["name"] = "Full name is required."
    elif len(name) > NAME_MAX:
        errors["name"] = "Full name is too long."

    email = (payload.get("email") or "").strip()
    if not email:
        errors["email"] = "Email is required."
    elif len(email) > EMAIL_MAX or not EMAIL_RE.match(email):
        errors["email"] = "Please enter a valid email address."

    date_str = (payload.get("date") or "").strip()
    parsed_date = None
    if not date_str:
        errors["date"] = "Please choose a date."
    else:
        try:
            parsed_date = datetime.strptime(date_str, "%Y-%m-%d").date()
            if parsed_date < date.today():
                errors["date"] = "Please pick today or a future date."
        except ValueError:
            errors["date"] = "Invalid date format."

    time_str = (payload.get("time") or "").strip()
    if not time_str:
        errors["time"] = "Please choose a time."
    elif not TIME_RE.match(time_str):
        errors["time"] = "Invalid time format."

    focus = (payload.get("focus") or "").strip()
    if not focus:
        errors["focus"] = "Please choose a focus area."
    elif len(focus) > FOCUS_MAX:
        errors["focus"] = "Focus area is too long."

    notes = (payload.get("notes") or "").strip()
    if len(notes) > NOTES_MAX:
        errors["notes"] = "Notes are too long."

    return errors, {
        "name": name,
        "email": email,
        "date": parsed_date,
        "time": time_str,
        "focus": focus,
        "notes": notes or None,
    }


def main():
    method = os.environ.get("REQUEST_METHOD", "GET").upper()
    if method == "OPTIONS":
        sys.stdout.write("Status: 204 No Content\r\n")
        sys.stdout.write("Allow: POST, OPTIONS\r\n")
        sys.stdout.write("\r\n")
        return
    if method != "POST":
        respond("405 Method Not Allowed", {"ok": False, "error": "method_not_allowed"})

    try:
        length = int(os.environ.get("CONTENT_LENGTH", "0") or "0")
    except ValueError:
        length = 0
    if length <= 0 or length > 16384:
        respond("400 Bad Request", {"ok": False, "error": "invalid_body_size"})

    raw = sys.stdin.buffer.read(length).decode("utf-8", errors="replace")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        respond("400 Bad Request", {"ok": False, "error": "invalid_json"})

    if not isinstance(payload, dict):
        respond("400 Bad Request", {"ok": False, "error": "invalid_payload"})

    errors, cleaned = validate(payload)
    if errors:
        respond("422 Unprocessable Entity", {"ok": False, "errors": errors})

    try:
        env = load_db_env()
    except OSError:
        sys.stderr.write("book.py: cannot read db credentials\n")
        respond("500 Internal Server Error", {"ok": False, "error": "config_unavailable"})

    source_ip = os.environ.get("REMOTE_ADDR") or None

    try:
        conn = psycopg2.connect(
            host=env.get("PGHOST", "db-internal"),
            port=int(env.get("PGPORT", "5432")),
            dbname=env.get("PGDATABASE", "waystar"),
            user=env["PGUSER"],
            password=env["PGPASSWORD"],
            connect_timeout=5,
            application_name="waystar-connect-web",
        )
    except (KeyError, psycopg2.OperationalError) as e:
        sys.stderr.write(f"book.py: db connect failed: {e}\n")
        respond("503 Service Unavailable", {"ok": False, "error": "db_unavailable"})

    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO appointments
                        (full_name, email, preferred_date, preferred_time,
                         focus, notes, source_ip)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING id, created_at
                    """,
                    (
                        cleaned["name"],
                        cleaned["email"],
                        cleaned["date"],
                        cleaned["time"],
                        cleaned["focus"],
                        cleaned["notes"],
                        source_ip,
                    ),
                )
                new_id, created_at = cur.fetchone()
    except psycopg2.Error as e:
        sys.stderr.write(f"book.py: insert failed: {e}\n")
        respond("500 Internal Server Error", {"ok": False, "error": "db_write_failed"})
    finally:
        try:
            conn.close()
        except Exception:
            pass

    respond("201 Created", {
        "ok": True,
        "id": new_id,
        "reference": f"WS-{str(new_id).zfill(6)}",
        "created_at": created_at.isoformat(),
    })


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        sys.stderr.write(f"book.py: unhandled error: {e}\n")
        respond("500 Internal Server Error", {"ok": False, "error": "internal_error"})
