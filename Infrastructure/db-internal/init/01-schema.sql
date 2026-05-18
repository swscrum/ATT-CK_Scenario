-- ============================================================================
--  01-schema.sql — Waystar Royco patient database schema
--
--  Runs on first container start, connected to the 'waystar' database
--  (created automatically by POSTGRES_DB).
--
--  Users:
--    waystar          — privileged owner (POSTGRES_USER; creds on Hans's box)
--    waystar-readonly — SELECT-only (creds breadcrumbed on John's workstation)
--    waystar-app      — INSERT-only on appointments; used by the public-
--                       facing Waystar Connect web booking form. Creds live
--                       on the apache host in /etc/waystar/db.env.
-- ============================================================================

-- Read-only application user.
-- Password intentionally weak — left unchanged since the initial deployment.
-- Breadcrumbed as: db-internal:5432:waystar:waystar-readonly:ChangeMe!2026
CREATE USER "waystar-readonly" WITH PASSWORD 'ChangeMe!2026';

GRANT CONNECT ON DATABASE waystar TO "waystar-readonly";
GRANT USAGE   ON SCHEMA  public  TO "waystar-readonly";

-- Web-app insert user (booking form on apache).
-- Password intentionally weak — never rotated since launch.
-- Stored on apache:/etc/waystar/db.env (640, www-data readable).
CREATE USER "waystar-app" WITH PASSWORD 'AppBooking!2026';

GRANT CONNECT ON DATABASE waystar TO "waystar-app";
GRANT USAGE   ON SCHEMA  public  TO "waystar-app";

-- ─── Tables ──────────────────────────────────────────────────────────────────

CREATE TABLE patients (
    id          SERIAL       PRIMARY KEY,
    first_name  VARCHAR(60)  NOT NULL,
    last_name   VARCHAR(60)  NOT NULL,
    dob         DATE         NOT NULL,
    gender      CHAR(1)      NOT NULL CHECK (gender IN ('M','F','D')),
    ins_number  VARCHAR(20)  NOT NULL UNIQUE,
    phone       VARCHAR(20),
    email       VARCHAR(120),
    street      VARCHAR(100),
    city        VARCHAR(60),
    postal_code CHAR(5),
    diagnosis   VARCHAR(20),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE session_notes (
    id           SERIAL       PRIMARY KEY,
    patient_id   INTEGER      NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    therapist    VARCHAR(80)  NOT NULL,
    session_date DATE         NOT NULL,
    session_type VARCHAR(30),
    duration_min SMALLINT,
    content      TEXT,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Inbound booking requests from the public-facing waystar-connect site.
-- These are NOT confirmed patients yet — staff triages them and creates
-- patient/session records from approved entries.
CREATE TABLE appointments (
    id            SERIAL       PRIMARY KEY,
    full_name     VARCHAR(120) NOT NULL,
    email         VARCHAR(160) NOT NULL,
    preferred_date DATE        NOT NULL,
    preferred_time VARCHAR(10) NOT NULL,
    focus         VARCHAR(80)  NOT NULL,
    notes         TEXT,
    source_ip     INET,
    status        VARCHAR(20)  NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','contacted','scheduled','declined')),
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX appointments_created_at_idx ON appointments (created_at DESC);
CREATE INDEX appointments_status_idx     ON appointments (status);

-- ─── Privileges ──────────────────────────────────────────────────────────────

GRANT SELECT ON patients, session_notes, appointments TO "waystar-readonly";

-- waystar-app: only what the booking form needs. INSERT on appointments and
-- USAGE on the auto-generated sequence (so SERIAL works). No SELECT on
-- patient data — a compromised webserver cannot enumerate patients via
-- these credentials alone. Column-level SELECT on (id, created_at) is
-- required so `INSERT ... RETURNING id, created_at` works without giving
-- read access to the personal-data columns.
GRANT INSERT                       ON appointments              TO "waystar-app";
GRANT SELECT (id, created_at)      ON appointments              TO "waystar-app";
GRANT USAGE, SELECT                ON SEQUENCE appointments_id_seq TO "waystar-app";
