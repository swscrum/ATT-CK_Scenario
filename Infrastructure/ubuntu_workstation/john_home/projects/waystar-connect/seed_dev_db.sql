-- Dev fixtures for Waystar Connect frontend work.
-- NOT real patient data. Synthetic records for local UI prototyping only.
-- The actual patient store lives behind db-internal; see .pgpass in this
-- directory for the read-only connection (PGPASSFILE is set in ~/.bashrc).

CREATE TABLE IF NOT EXISTS therapists (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    speciality  TEXT
);

CREATE TABLE IF NOT EXISTS patients (
    id            INTEGER PRIMARY KEY,
    full_name     TEXT NOT NULL,
    email         TEXT,
    intake_date   TEXT,
    therapist_id  INTEGER REFERENCES therapists(id)
);

CREATE TABLE IF NOT EXISTS sessions (
    id            INTEGER PRIMARY KEY,
    patient_id    INTEGER REFERENCES patients(id),
    therapist_id  INTEGER REFERENCES therapists(id),
    scheduled_at  TEXT,
    status        TEXT
);

-- Synthetic therapist fixtures. Names are fictional and unrelated to any
-- real Waystar staff (see ~/Documents/Useful contacts.md for the real org).
INSERT INTO therapists (id, name, speciality) VALUES
    (1, 'Dr. E. Brooks',  'CBT'),
    (2, 'Dr. M. Halsey',  'Trauma'),
    (3, 'Dr. J. Carter',  'Family');

INSERT INTO patients (id, full_name, email, intake_date, therapist_id) VALUES
    (1, 'Test Patient One',   'test1@example.com', '2026-01-15', 1),
    (2, 'Test Patient Two',   'test2@example.com', '2026-01-22', 2),
    (3, 'Test Patient Three', 'test3@example.com', '2026-02-04', 1),
    (4, 'Test Patient Four',  'test4@example.com', '2026-02-11', 3),
    (5, 'Test Patient Five',  'test5@example.com', '2026-02-18', 2),
    (6, 'Test Patient Six',   'test6@example.com', '2026-02-25', 1),
    (7, 'Test Patient Seven', 'test7@example.com', '2026-03-04', 3),
    (8, 'Test Patient Eight', 'test8@example.com', '2026-03-11', 2);

INSERT INTO sessions (patient_id, therapist_id, scheduled_at, status) VALUES
    (1, 1, '2026-05-20 10:00', 'scheduled'),
    (2, 2, '2026-05-20 11:00', 'scheduled'),
    (3, 1, '2026-05-21 09:00', 'completed'),
    (4, 3, '2026-05-22 14:00', 'scheduled'),
    (5, 2, '2026-05-23 10:00', 'cancelled');
