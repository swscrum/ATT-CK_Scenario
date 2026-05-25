-- Local SQLite patient cache for Luke Smith.
-- Materialised into ~luke.smith/.local/share/waystar-psyc/patients.sqlite
-- during image build. Models the thin offline working file an anglophone
-- clinician would keep alongside the central PostgreSQL db (db-internal).
--
-- Scoped to Luke's caseload only — patients 1, 2, 5, 8 from db-internal's
-- 02-seed.sql. The `patient_summary` table is the one referenced by
-- ~/.bash_history (`SELECT * FROM patient_summary LIMIT 5`) and the
-- `localnotes` alias in ~/.bashrc.
--
-- LAB ONLY — fictional patients, used by the attack chain as the Phase 11
-- local-cache loot artefact (T1005 — Data from Local System).

PRAGMA foreign_keys = ON;

CREATE TABLE patient_summary (
    patient_id      INTEGER PRIMARY KEY,
    last_name       TEXT NOT NULL,
    first_name      TEXT NOT NULL,
    diagnosis_icd10 TEXT NOT NULL,
    primary_concern TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    next_session    TEXT,
    sessions_total  INTEGER NOT NULL DEFAULT 0,
    risk_flag       TEXT NOT NULL DEFAULT 'none'
                    CHECK (risk_flag IN ('none','watch','elevated','high'))
);

CREATE TABLE recent_session_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id      INTEGER NOT NULL REFERENCES patient_summary(patient_id),
    session_date    TEXT NOT NULL,
    session_type    TEXT NOT NULL,
    headline        TEXT NOT NULL
);

INSERT INTO patient_summary
    (patient_id, last_name, first_name, diagnosis_icd10, primary_concern, last_seen, next_session, sessions_total, risk_flag)
VALUES
    (1, 'Müller',  'Thomas',    'F32.1', 'Depressive episode post job loss',          '2026-05-06', '2026-05-27', 5,  'watch'),
    (2, 'Schmidt', 'Maria',     'F41.1', 'Adult ADHD, executive dysfunction',         '2026-05-02', '2026-05-23', 3,  'none'),
    (5, 'Weber',   'Stefan',    'F10.2', 'Generalised anxiety, prior benzo history',  '2026-04-30', '2026-05-28', 10, 'watch'),
    (8, 'Becker',  'Nicole',    'F32.2', 'OCD, contamination + ritual handwashing',   '2026-05-19', '2026-05-26', 2,  'elevated');

INSERT INTO recent_session_log (patient_id, session_date, session_type, headline) VALUES
    (1, '2026-05-06', 'Individual Therapy', 'Part-time consulting secured; PHQ-9 17→11'),
    (2, '2026-05-02', 'Individual Therapy', 'Time-boxing sticks; sleep hygiene next'),
    (5, '2026-04-30', 'Individual Therapy', 'GAD-7 16→9; planning monthly maintenance'),
    (8, '2026-05-19', 'Individual Therapy', 'ERP hierarchy started, SUD 5→3 in session'),
    (8, '2026-05-12', 'Initial Assessment', 'Y-BOCS 26; spouse joining from session 3');
