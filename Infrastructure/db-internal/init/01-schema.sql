-- ============================================================================
--  01-schema.sql — Waystar Royco patient database schema
--
--  Runs on first container start, connected to the 'waystar' database
--  (created automatically by POSTGRES_DB).
--
--  Users:
--    waystar          — privileged owner (POSTGRES_USER; creds on Hans's box)
--    waystar-readonly — SELECT-only (creds breadcrumbed on John's workstation)
-- ============================================================================

-- Read-only application user.
-- Password intentionally weak — left unchanged since the initial deployment.
-- Breadcrumbed as: db-internal:5432:waystar:waystar-readonly:ChangeMe!2026
CREATE USER "waystar-readonly" WITH PASSWORD 'ChangeMe!2026';

GRANT CONNECT ON DATABASE waystar TO "waystar-readonly";
GRANT USAGE   ON SCHEMA  public  TO "waystar-readonly";

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

-- ─── Privileges ──────────────────────────────────────────────────────────────

GRANT SELECT ON patients, session_notes TO "waystar-readonly";
