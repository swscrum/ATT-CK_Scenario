-- ============================================================================
--  02-seed.sql — Fictional patient records for Waystar Royco
--
--  All names, addresses, insurance numbers, and clinical notes are entirely
--  fictional and generated for demonstration purposes only.
-- ============================================================================

INSERT INTO patients
    (first_name, last_name, dob, gender, ins_number, phone, email,
     street, city, postal_code, diagnosis)
VALUES
-- 1–10
('Thomas',     'Müller',      '1978-03-14', 'M', 'A123456789', '+49 89 12345670',  'thomas.mueller@gmx.de',         'Leopoldstr. 12',          'München',    '80331', 'F32.1'),
('Maria',      'Schmidt',     '1985-07-22', 'F', 'B234567890', '+49 30 23456781',  'maria.schmidt@web.de',          'Berliner Str. 45',        'Berlin',     '10115', 'F41.1'),
('Andreas',    'Schneider',   '1972-11-05', 'M', 'C345678901', '+49 40 34567892',  'a.schneider@t-online.de',       'Reeperbahn 8',            'Hamburg',    '20095', 'F33.0'),
('Sabine',     'Fischer',     '1990-02-18', 'F', 'D456789012', '+49 221 45678903', 'sabine.fischer@web.de',         'Domkloster 2',            'Köln',       '50667', 'F43.1'),
('Stefan',     'Weber',       '1968-09-30', 'M', 'E567890123', '+49 69 56789014',  's.weber@freenet.de',            'Zeil 22',                 'Frankfurt',  '60311', 'F10.2'),
('Claudia',    'Meyer',       '1982-04-12', 'F', 'F678901234', '+49 711 67890125', 'claudia.meyer@gmail.com',       'Königstr. 1',             'Stuttgart',  '70173', 'F40.1'),
('Christian',  'Wagner',      '1975-12-01', 'M', 'G789012345', '+49 211 78901236', 'c.wagner@yahoo.de',             'Königsallee 28',          'Düsseldorf', '40213', 'F60.3'),
('Nicole',     'Becker',      '1988-06-25', 'F', 'H890123456', '+49 341 89012347', 'nicole.becker@gmx.de',          'Augustusplatz 5',         'Leipzig',    '04109', 'F32.2'),
('Klaus',      'Schulz',      '1965-08-17', 'M', 'J901234567', '+49 231 90123458', 'k.schulz@web.de',               'Westenhellweg 18',        'Dortmund',   '44135', 'F31.1'),
('Sandra',     'Hoffmann',    '1993-01-09', 'F', 'K012345678', '+49 201 01234569', 'sandra.hoffmann@t-online.de',   'Limbecker Platz 1',       'Essen',      '45127', 'F41.0'),
-- 11–20
('Wolfgang',   'Schäfer',    '1960-05-27', 'M', 'L123456780', '+49 421 12345600', 'w.schaefer@freenet.de',         'Obernstr. 4',             'Bremen',     '28195', 'F32.1'),
('Petra',      'Koch',        '1986-10-14', 'F', 'M234567891', '+49 351 23456711', 'petra.koch@gmail.com',          'Prager Str. 8',           'Dresden',    '01067', 'F41.1'),
('Jürgen',    'Bauer',       '1971-03-08', 'M', 'N345678902', '+49 511 34567822', 'juergen.bauer@gmx.de',          'Georgstr. 11',            'Hannover',   '30159', 'F43.1'),
('Monika',     'Richter',     '1979-07-31', 'F', 'P456789013', '+49 911 45678933', 'monika.richter@web.de',         'Kaiserstr. 3',            'Nürnberg',   '90402', 'F50.0'),
('Frank',      'Klein',       '1983-11-19', 'M', 'Q567890124', '+49 821 56789044', 'frank.klein@yahoo.de',          'Maximilianstr. 6',        'Augsburg',   '86150', 'F10.2'),
('Stefanie',   'Wolf',        '1991-02-28', 'F', 'R678901235', '+49 611 67890155', 's.wolf@gmx.de',                 'Wilhelmstr. 14',          'Wiesbaden',  '65185', 'F40.1'),
('Markus',     'Schröder',   '1974-06-15', 'M', 'S789012346', '+49 761 78901266', 'markus.schroeder@t-online.de',  'Kaiser-Joseph-Str. 2',    'Freiburg',   '79098', 'F32.2'),
('Andrea',     'Neumann',     '1987-09-04', 'F', 'T890123457', '+49 234 89012377', 'andrea.neumann@web.de',         'Huestr. 22',              'Bochum',     '44787', 'F41.1'),
('Martin',     'Schwarz',     '1969-12-23', 'M', 'U901234568', '+49 228 90123488', 'm.schwarz@freenet.de',          'Am Hof 5',                'Bonn',       '53111', 'F33.0'),
('Christine',  'Zimmermann',  '1992-04-07', 'F', 'V012345679', '+49 621 01234599', 'c.zimmermann@gmail.com',        'Planken 18',              'Mannheim',   '68161', 'F32.1'),
-- 21–30
('Daniel',     'Braun',       '1980-08-16', 'M', 'W123456780', '+49 89 12345681',  'daniel.braun@gmx.de',           'Schwabing Str. 44',       'München',    '80331', 'F41.0'),
('Karin',      'Krüger',     '1976-01-29', 'F', 'X234567891', '+49 30 23456792',  'karin.krueger@web.de',          'Prenzlauer Berg 12',      'Berlin',     '10115', 'F60.3'),
('Robert',     'Hofmann',     '1984-05-11', 'M', 'Y345678902', '+49 40 34567903',  'robert.hofmann@t-online.de',    'Eppendorf Str. 3',        'Hamburg',    '20095', 'F31.1'),
('Julia',      'Hartmann',    '1989-09-24', 'F', 'Z456789013', '+49 221 45679014', 'julia.hartmann@yahoo.de',       'Neumarkt 7',              'Köln',       '50667', 'F43.1'),
('Sebastian',  'Lange',       '1973-02-06', 'M', 'A567890124', '+49 69 56790125',  's.lange@freenet.de',            'Sachsenhausen 15',        'Frankfurt',  '60311', 'F32.1'),
('Birgit',     'Schmitt',     '1981-06-19', 'F', 'B678901235', '+49 711 67901236', 'birgit.schmitt@gmx.de',         'Marktplatz 4',            'Stuttgart',  '70173', 'F41.1'),
('Florian',    'Werner',      '1994-10-03', 'M', 'C789012346', '+49 211 79012347', 'florian.werner@gmail.com',      'Flinger Str. 8',          'Düsseldorf', '40213', 'F40.1'),
('Anja',       'Schmitz',     '1978-03-27', 'F', 'D890123457', '+49 341 89123458', 'anja.schmitz@web.de',           'Grimmaische Str. 22',     'Leipzig',    '04109', 'F50.0'),
('Patrick',    'Krause',      '1967-07-14', 'M', 'E901234568', '+49 231 90234569', 'p.krause@t-online.de',          'Kampstr. 9',              'Dortmund',   '44135', 'F10.2'),
('Laura',      'Meier',       '1995-11-28', 'F', 'F012345679', '+49 201 01345670', 'laura.meier@freenet.de',        'Rüttenscheider Str. 5',  'Essen',      '45127', 'F32.2'),
-- 31–40
('Jan',        'Lehmann',     '1970-04-10', 'M', 'G123456780', '+49 421 12456781', 'jan.lehmann@gmx.de',            'Sögestr. 14',            'Bremen',     '28195', 'F33.0'),
('Katharina',  'Köhler',     '1988-08-22', 'F', 'H234567891', '+49 351 23567892', 'katharina.koehler@gmail.com',   'Altmarkt 3',              'Dresden',    '01067', 'F41.0'),
('Tim',        'Herrmann',    '1977-12-05', 'M', 'J345678902', '+49 511 34678903', 'tim.herrmann@yahoo.de',         'Bahnhofstr. 28',          'Hannover',   '30159', 'F32.1'),
('Franziska',  'Walter',      '1991-03-18', 'F', 'K456789013', '+49 911 45789014', 'franziska.walter@web.de',       'Königstr. 12',            'Nürnberg',   '90402', 'F60.3'),
('Nico',       'Mayer',       '1985-07-01', 'M', 'L567890124', '+49 821 56890125', 'nico.mayer@t-online.de',        'Annastr. 6',              'Augsburg',   '86150', 'F41.1'),
('Lena',       'König',      '1998-10-14', 'F', 'M678901235', '+49 611 67901236', 'lena.koenig@gmx.de',            'Luisenplatz 9',           'Wiesbaden',  '65185', 'F43.1'),
('Leon',       'Jung',        '1982-01-27', 'M', 'N789012346', '+49 761 79012347', 'leon.jung@freenet.de',          'Bertoldstr. 11',          'Freiburg',   '79098', 'F32.2'),
('Emma',       'Fuchs',       '1996-05-09', 'F', 'P890123457', '+49 234 89123458', 'emma.fuchs@gmail.com',          'Viktoriastr. 33',         'Bochum',     '44787', 'F40.1'),
('Simon',      'Kaiser',      '1974-09-21', 'M', 'Q901234568', '+49 228 90234569', 's.kaiser@gmx.de',               'Quantiusstr. 7',          'Bonn',       '53111', 'F31.1'),
('Hannah',     'Roth',        '1989-02-04', 'F', 'R012345679', '+49 621 01345670', 'hannah.roth@web.de',            'Breite Str. 5',           'Mannheim',   '68161', 'F41.0'),
-- 41–50
('David',      'Müller',     '1979-06-17', 'M', 'S123456780', '+49 89 12456781',  'd.mueller@t-online.de',         'Schelling Str. 18',       'München',    '80331', 'F32.1'),
('Lea',        'Schmidt',     '1993-10-30', 'F', 'T234567891', '+49 30 23567892',  'lea.schmidt@yahoo.de',          'Friedrichstr. 44',        'Berlin',     '10115', 'F33.0'),
('Alexander',  'Schneider',   '1966-03-13', 'M', 'U345678902', '+49 40 34678903',  'a.schneider2@web.de',           'Grindelallee 6',          'Hamburg',    '20095', 'F10.2'),
('Lara',       'Fischer',     '1997-07-26', 'F', 'V456789013', '+49 221 45789014', 'lara.fischer@freenet.de',       'Breite Str. 25',          'Köln',       '50667', 'F41.1'),
('Lukas',      'Weber',       '1971-11-08', 'M', 'W567890124', '+49 69 56890125',  'lukas.weber@gmx.de',            'Berger Str. 12',          'Frankfurt',  '60311', 'F43.1'),
('Sophie',     'Meyer',       '1986-04-21', 'F', 'X678901235', '+49 711 67901236', 'sophie.meyer@gmail.com',        'Rotebühlplatz 9',        'Stuttgart',  '70173', 'F60.3'),
('Maximilian', 'Wagner',      '1990-08-04', 'M', 'Y789012346', '+49 211 79012347', 'm.wagner@t-online.de',          'Schadowstr. 3',           'Düsseldorf', '40213', 'F32.1'),
('Mia',        'Becker',      '1994-12-17', 'F', 'Z890123457', '+49 341 89123458', 'mia.becker@web.de',             'Nikolaistr. 8',           'Leipzig',    '04109', 'F41.0'),
('Johannes',   'Schulz',      '1968-05-30', 'M', 'A901234568', '+49 231 90234569', 'j.schulz@freenet.de',           'Silberstr. 21',           'Dortmund',   '44135', 'F50.0'),
('Lisa',       'Hoffmann',    '1987-09-12', 'F', 'B012345679', '+49 201 01345670', 'lisa.hoffmann@gmx.de',          'Limbecker Str. 14',       'Essen',      '45127', 'F32.2'),
-- 51–60
('Hans',       'Schäfer',    '1962-02-24', 'M', 'C123456780', '+49 421 12456781', 'hans.schaefer@yahoo.de',        'Bahnhofsplatz 2',         'Bremen',     '28195', 'F31.1'),
('Sarah',      'Koch',        '1999-06-07', 'F', 'D234567891', '+49 351 23567892', 'sarah.koch@gmail.com',          'Striesener Str. 4',       'Dresden',    '01067', 'F41.1'),
('Peter',      'Bauer',       '1963-10-19', 'M', 'E345678902', '+49 511 34678903', 'peter.bauer@web.de',            'Lavesstr. 8',             'Hannover',   '30159', 'F33.0'),
('Melanie',    'Richter',     '1984-03-02', 'F', 'F456789013', '+49 911 45789014', 'melanie.richter@t-online.de',   'Adlerstr. 16',            'Nürnberg',   '90402', 'F40.1'),
('Michael',    'Klein',       '1977-07-15', 'M', 'G567890124', '+49 821 56890125', 'm.klein@freenet.de',            'Bürgermeister-Fischer-Str. 3', 'Augsburg', '86150', 'F32.1'),
('Natalie',    'Wolf',        '1992-11-28', 'F', 'H678901235', '+49 611 67901236', 'natalie.wolf@gmx.de',           'Taunusstr. 22',           'Wiesbaden',  '65185', 'F43.1'),
('Thomas',     'Schröder',   '1973-04-11', 'M', 'J789012346', '+49 761 79012347', 't.schroeder@gmail.com',         'Friedrichring 5',         'Freiburg',   '79098', 'F60.3'),
('Maria',      'Neumann',     '1980-08-24', 'F', 'K890123457', '+49 234 89123458', 'maria.neumann@web.de',          'Springerplatz 11',        'Bochum',     '44787', 'F32.2'),
('Andreas',    'Schwarz',     '1988-01-06', 'M', 'L901234568', '+49 228 90234569', 'a.schwarz@yahoo.de',            'Friedensplatz 8',         'Bonn',       '53111', 'F41.0'),
('Sabine',     'Zimmermann',  '1995-05-19', 'F', 'M012345679', '+49 621 01345670', 's.zimmermann@t-online.de',      'Paradeplatz 3',           'Mannheim',   '68161', 'F31.1'),
-- 61–70
('Stefan',     'Braun',       '1969-09-01', 'M', 'N123456780', '+49 89 12456782',  'stefan.braun@web.de',           'Tengstr. 28',             'München',    '80331', 'F10.2'),
('Claudia',    'Krüger',     '1983-12-14', 'F', 'P234567891', '+49 30 23567893',  'claudia.krueger@freenet.de',    'Kastanienallee 7',        'Berlin',     '10115', 'F32.1'),
('Christian',  'Hofmann',     '1978-04-27', 'M', 'Q345678902', '+49 40 34678904',  'c.hofmann@gmx.de',              'Isestr. 15',              'Hamburg',    '20095', 'F41.1'),
('Nicole',     'Hartmann',    '1991-08-10', 'F', 'R456789013', '+49 221 45789015', 'nicole.hartmann@gmail.com',     'Ehrenstr. 9',             'Köln',       '50667', 'F40.1'),
('Klaus',      'Lange',       '1964-01-22', 'M', 'S567890124', '+49 69 56890126',  'k.lange@yahoo.de',              'Goethestr. 44',           'Frankfurt',  '60311', 'F33.0'),
('Sandra',     'Schmitt',     '1997-05-05', 'F', 'T678901235', '+49 711 67901237', 's.schmitt@web.de',              'Eberhardstr. 6',          'Stuttgart',  '70173', 'F50.0'),
('Wolfgang',   'Werner',      '1961-09-17', 'M', 'U789012346', '+49 211 79012348', 'w.werner@t-online.de',          'Immermannstr. 22',        'Düsseldorf', '40213', 'F32.2'),
('Petra',      'Schmitz',     '1985-01-30', 'F', 'V890123457', '+49 341 89123459', 'petra.schmitz@freenet.de',      'Ritterstr. 3',            'Leipzig',    '04109', 'F41.1'),
('Jürgen',    'Krause',      '1970-06-12', 'M', 'W901234568', '+49 231 90234570', 'j.krause@gmx.de',               'Hansastr. 18',            'Dortmund',   '44135', 'F60.3'),
('Monika',     'Meier',       '1994-10-25', 'F', 'X012345679', '+49 201 01345671', 'm.meier@gmail.com',             'Rellinghauser Str. 14',   'Essen',      '45127', 'F32.1'),
-- 71–80
('Frank',      'Lehmann',     '1967-03-08', 'M', 'Y123456780', '+49 421 12456783', 'frank.lehmann@yahoo.de',        'Contrescarpe 8',          'Bremen',     '28195', 'F31.1'),
('Stefanie',   'Köhler',     '1989-07-21', 'F', 'Z234567891', '+49 351 23567894', 's.koehler@web.de',              'Neumarkt 16',             'Dresden',    '01067', 'F43.1'),
('Markus',     'Herrmann',    '1975-11-03', 'M', 'A345678902', '+49 511 34678905', 'm.herrmann@t-online.de',        'Ernst-August-Platz 2',    'Hannover',   '30159', 'F41.0'),
('Andrea',     'Walter',      '1999-02-15', 'F', 'B456789013', '+49 911 45789016', 'andrea.walter@freenet.de',      'Lorenzer Platz 5',        'Nürnberg',   '90402', 'F40.1'),
('Martin',     'Mayer',       '1981-06-28', 'M', 'C567890124', '+49 821 56890127', 'm.mayer@gmx.de',                'Stadtberger Str. 12',     'Augsburg',   '86150', 'F32.1'),
('Christine',  'König',      '1972-10-10', 'F', 'D678901235', '+49 611 67901238', 'c.koenig@gmail.com',            'Rheinstr. 28',            'Wiesbaden',  '65185', 'F41.1'),
('Daniel',     'Jung',        '1996-03-23', 'M', 'E789012346', '+49 761 79012349', 'd.jung@yahoo.de',               'Freiburger Str. 6',       'Freiburg',   '79098', 'F33.0'),
('Karin',      'Fuchs',       '1983-07-06', 'F', 'F890123457', '+49 234 89123460', 'karin.fuchs@web.de',            'Alleestr. 22',            'Bochum',     '44787', 'F32.2'),
('Robert',     'Kaiser',      '1968-11-19', 'M', 'G901234568', '+49 228 90234571', 'r.kaiser@t-online.de',          'Bottlerplatz 8',          'Bonn',       '53111', 'F10.2'),
('Julia',      'Roth',        '1990-04-02', 'F', 'H012345679', '+49 621 01345672', 'julia.roth@freenet.de',         'O7 Quadrat 3',            'Mannheim',   '68161', 'F41.0');


-- ─── Session notes (distributed across ~55 of the 80 patients) ───────────────

INSERT INTO session_notes (patient_id, therapist, session_date, session_type, duration_min, content) VALUES
-- Patient 1 — Thomas Müller (F32.1 depressive episode)
(1,  'Dr. Hanna Becker', '2025-09-04', 'Erstgespräch',     50, 'Patient berichtet von anhaltender Niedergeschlagenheit seit ca. 6 Monaten, Schlafstörungen und sozialem Rückzug. Anamnese unauffällig. Behandlungsplan wird erarbeitet.'),
(1,  'Dr. Hanna Becker', '2025-09-18', 'Einzeltherapie',   50, 'Stimmung leicht verbessert. Patient hat Schlafprotokoll geführt. Aktivierungsplan besprochen; erste Spaziergänge absolviert. Nächste Sitzung in zwei Wochen.'),
(1,  'Dr. Hanna Becker', '2025-10-02', 'Einzeltherapie',   50, 'Rückfall nach Konflikt im Arbeitsumfeld. Kognitive Umstrukturierung eingeleitet. Hausaufgabe: Gedankentagebuch führen.'),

-- Patient 2 — Maria Schmidt (F41.1 generalized anxiety)
(2,  'Dr. Klaus Wirth',  '2025-08-12', 'Erstgespräch',     50, 'Patientin klagt über chronische Anspannung, Grübeln und körperliche Beschwerden (Herzklopfen, Magenprobleme). Erstdiagnose GAD. Psychoedukation begonnen.'),
(2,  'Dr. Klaus Wirth',  '2025-08-26', 'Einzeltherapie',   50, 'Atemübungen und Progressive Muskelentspannung eingeführt. Patientin berichtet von ersten Fortschritten beim Abendschlaf.'),
(2,  'Dr. Klaus Wirth',  '2025-09-09', 'Einzeltherapie',   50, 'Sorgenexposition durchgeführt. Patientin zeigt gutes Verständnis der kognitiven Techniken. Alltagsbelastung weiterhin hoch durch Pflegesituation der Mutter.'),
(2,  'Dr. Klaus Wirth',  '2025-09-23', 'Einzeltherapie',   50, 'Stabilisierung erkennbar. Ressourcenarbeit intensiviert. Symptomtagebuch zeigt Reduktion der Anspannungsspitzen.'),

-- Patient 3 — Andreas Schneider (F33.0 recurrent depression)
(3,  'Dr. Sabine Kohl',  '2025-07-15', 'Erstgespräch',     50, 'Dritte depressive Episode in fünf Jahren. Patient hat positive Erfahrungen mit VT. Medikation durch niedergelassenen Psychiater läuft parallel.'),
(3,  'Dr. Sabine Kohl',  '2025-07-29', 'Einzeltherapie',   50, 'Rückfallprävention im Fokus. Frühindikatoren der Depression erarbeitet. Notfallkarte erstellt.'),
(3,  'Dr. Sabine Kohl',  '2025-08-12', 'Einzeltherapie',   50, 'Stimmung stabil. Wiedereingliederung in Arbeit besprochen. Belastungserprobung geplant.'),

-- Patient 4 — Sabine Fischer (F43.1 PTSD)
(4,  'Dr. Markus Vogel', '2025-10-07', 'Erstgespräch',     50, 'Traumatisches Ereignis vor 18 Monaten (Verkehrsunfall). Flashbacks, Vermeidungsverhalten, Hypervigilanz. Stabilisierungsphase eingeleitet.'),
(4,  'Dr. Markus Vogel', '2025-10-21', 'Einzeltherapie',   50, 'Sichere-Ort-Übung gut angenommen. Keine Selbstverletzungsgedanken. Patientin zeigt hohe Therapiemotivation.'),
(4,  'Dr. Markus Vogel', '2025-11-04', 'Einzeltherapie',   50, 'Erste traumafokussierte Exposition begonnen (imaginale Exposition nach Ehlers/Clark). Patientin belastet, aber stabil.'),

-- Patient 5 — Stefan Weber (F10.2 alcohol use disorder)
(5,  'Dr. Klaus Wirth',  '2025-09-02', 'Erstgespräch',     50, 'Patient wurde durch Hausarzt überwiesen. Täglicher Konsum von ca. 4–6 Bier. Motivation zur Abstinenz vorhanden, jedoch ambivalent. Motivational Interviewing begonnen.'),
(5,  'Dr. Klaus Wirth',  '2025-09-16', 'Einzeltherapie',   50, 'Patient berichtet von fünf abstinenten Tagen. Entzugssymptome leicht (Schlafstörungen, Unruhe). Rückfallpräventionsplan erstellt.'),
(5,  'Dr. Klaus Wirth',  '2025-09-30', 'Einzeltherapie',   50, 'Rückfall nach Betriebsfeier. Patient erscheint reuevoll. Triggerliste aktualisiert. Abstinenzentscheidung erneuert.'),

-- Patient 6 — Claudia Meyer (F40.1 social phobia)
(6,  'Dr. Hanna Becker', '2025-08-05', 'Erstgespräch',     50, 'Patientin meidet öffentliche Situationen, Meetings, Telefonate. Blushing und Schwitzen als Kernsymptome. Exposition mit Reaktionsmanagement geplant.'),
(6,  'Dr. Hanna Becker', '2025-08-19', 'Einzeltherapie',   50, 'Hierarchie der Angstsituationen erstellt. Erste In-vivo-Exposition (Supermarkt) durchgeführt — Angst von 8/10 auf 4/10 gesunken.'),
(6,  'Dr. Hanna Becker', '2025-09-02', 'Einzeltherapie',   50, 'Patientin berichtet von spontaner Exposition im Berufsalltag. Sicherheitsverhalten reduziert. Aufmerksamkeitstraining (SAT) begonnen.'),

-- Patient 7 — Christian Wagner (F60.3 EUPD/BPD)
(7,  'Dr. Sabine Kohl',  '2025-07-08', 'Erstgespräch',     50, 'Ausgeprägte affektive Instabilität, impulsive Handlungen, chronische Leere. DBT-Konzept erläutert. Patient motiviert.'),
(7,  'Dr. Sabine Kohl',  '2025-07-22', 'Einzeltherapie',   50, 'Mindfulness-Modul begonnen. TIPP-Fertigkeiten eingeführt. Keine akuten Selbstverletzungen.'),
(7,  'Dr. Sabine Kohl',  '2025-08-05', 'Einzeltherapie',   50, 'Krisenplan aktualisiert nach Vorfall mit Ex-Partner (Stalking-Vorwürfe). Patient stabil; rechtliche Beratung empfohlen.'),
(7,  'Dr. Sabine Kohl',  '2025-08-19', 'Gruppentherapie',  90, 'DBT-Fertigkeitengruppe: Stresstoleranz-Modul. Patient aktiv beteiligt, positive Rückmeldung von Mitpatienten.'),

-- Patient 8 — Nicole Becker (F32.2 severe depression)
(8,  'Dr. Markus Vogel', '2025-06-10', 'Erstgespräch',     50, 'Schwere depressive Episode mit Suizidideen ohne konkreten Plan. Sicherheitsabklärung durchgeführt. Stationäre Behandlung angeboten; Patientin lehnt ab. Engmaschige Anbindung vereinbart.'),
(8,  'Dr. Markus Vogel', '2025-06-17', 'Krisenintervention',50, 'Patientin nach Streit mit Partner in akuter Krise. Notfallgespräch. Suizidalität latent, kein konkreter Plan. Krisenplan aktiviert.'),
(8,  'Dr. Markus Vogel', '2025-07-01', 'Einzeltherapie',   50, 'Patientin stabil, Medikation (SSRI) angepasst durch Psychiater. Verhaltensaktivierung begonnen.'),
(8,  'Dr. Markus Vogel', '2025-07-15', 'Einzeltherapie',   50, 'Deutliche Stimmungsverbesserung. Schlaf stabilisiert. Soziale Kontakte wieder aufgenommen. Sitzungsfrequenz auf zweiwöchentlich reduziert.'),
(8,  'Dr. Markus Vogel', '2025-07-29', 'Einzeltherapie',   50, 'Ressourcenaktivierung. Patientin nimmt Hobbys wieder auf. Langfristiger Therapieplan besprochen.'),

-- Patient 9 — Klaus Schulz (F31.1 bipolar)
(9,  'Dr. Hanna Becker', '2025-08-20', 'Erstgespräch',     50, 'Bekannte bipolare Störung Typ I. Letzte Manie vor 14 Monaten. Aktuell euthym unter Lithium. Ziel: Rezidivprophylaxe und Psychoedukation.'),
(9,  'Dr. Hanna Becker', '2025-09-03', 'Einzeltherapie',   50, 'Frühwarnsystem für manische Episoden erarbeitet. Patient kennt Prodromalsymptome gut. Schlafhygiene als Schutzfaktor besprochen.'),

-- Patient 10 — Sandra Hoffmann (F41.0 panic disorder)
(10, 'Dr. Klaus Wirth',  '2025-09-11', 'Erstgespräch',     50, 'Erste Panikattacke vor sechs Monaten im Supermarkt. Seitdem Agoraphobie und Vermeidung. Erklärungsmodell der Panik erläutert.'),
(10, 'Dr. Klaus Wirth',  '2025-09-25', 'Einzeltherapie',   50, 'Interoceptive Exposition durchgeführt (Hyperventilation, Drehstuhl). Patientin ängstlich, aber kooperativ. Körperliche Auslöser gut erkannt.'),
(10, 'Dr. Klaus Wirth',  '2025-10-09', 'Einzeltherapie',   50, 'In-vivo-Exposition im Supermarkt mit Therapeut. Angstpeak bei 7/10, Abklingen auf 2/10 nach 40 Minuten. Patientin sehr erleichtert.'),

-- Patient 11 — Wolfgang Schäfer (F32.1)
(11, 'Dr. Sabine Kohl',  '2025-10-14', 'Erstgespräch',     50, 'Patient seit Renteneintritt depressiv. Verlust von Tagesstruktur und sozialer Einbindung. Verhaltensaktivierung und Sinnfindung im Fokus.'),
(11, 'Dr. Sabine Kohl',  '2025-10-28', 'Einzeltherapie',   50, 'Wochenplan entwickelt. Patient hat Volkshochschulkurs angemeldet. Stimmung leicht aufgehellt.'),

-- Patient 13 — Jürgen Bauer (F43.1 PTSD)
(13, 'Dr. Markus Vogel', '2025-09-16', 'Erstgespräch',     50, 'Traumatisierung durch Arbeitsunfall (Chemikaliensturz). Symptome: Intrusionen, Schreckhaftigkeit, Vermeidung des Betriebs. AU seit drei Monaten.'),
(13, 'Dr. Markus Vogel', '2025-09-30', 'Einzeltherapie',   50, 'Stabilisierungsphase. Sicherheitssignal-Übung und Container-Technik eingeführt. Patient kann Techniken anwenden.'),
(13, 'Dr. Markus Vogel', '2025-10-14', 'Einzeltherapie',   50, 'Schrittweise Annäherung an Stimuli (Gerüche). Erste Exposition mit Berichten über Unfall. Patient belastet.'),

-- Patient 14 — Monika Richter (F50.0 anorexia)
(14, 'Dr. Hanna Becker', '2025-07-22', 'Erstgespräch',     50, 'BMI 16,2. Patientin kommt auf Druck der Familie. Ambivalenz bezüglich Veränderung. Motivational Interviewing. Ernährungsberatung parallel vereinbart.'),
(14, 'Dr. Hanna Becker', '2025-08-05', 'Einzeltherapie',   50, 'Körperbild-Übungen begonnen. Patientin berichtet von geringfügiger Gewichtszunahme (+0,4 kg). Perfektionismusthema bearbeitet.'),
(14, 'Dr. Hanna Becker', '2025-08-19', 'Einzeltherapie',   50, 'Rückschritt: Gewicht geringfügig gesunken. Stationäre Einweisung erneut besprochen — Patientin weiterhin ablehnend. Engmaschige Anbindung.'),

-- Patient 17 — Markus Schröder (F32.2)
(17, 'Dr. Klaus Wirth',  '2025-08-26', 'Erstgespräch',     50, 'Schwere depressive Symptomatik nach Scheidung und Jobverlust. Keine Suizidalität. Patient schwer zugänglich, wenig Verbalisierung.'),
(17, 'Dr. Klaus Wirth',  '2025-09-09', 'Einzeltherapie',   50, 'Verhaltensaktivierung begonnen. Geringer Fortschritt. Einbezug von Rollenklärung (Vater) als Motivation.'),

-- Patient 18 — Andrea Neumann (F41.1)
(18, 'Dr. Sabine Kohl',  '2025-09-23', 'Erstgespräch',     50, 'Sorgen um Gesundheit, Finanzen und Beziehung dominieren Alltag. Patientin schläft schlecht, ist erschöpft. CBT für GAD begonnen.'),
(18, 'Dr. Sabine Kohl',  '2025-10-07', 'Einzeltherapie',   50, 'Sorgenprotokoll geführt. Unterscheidung zwischen lösbaren und unlösbaren Sorgen erarbeitet. Ergebnis: 70% unlösbar, Akzeptanzarbeit eingeleitet.'),

-- Patient 20 — Christine Zimmermann (F32.1)
(20, 'Dr. Markus Vogel', '2025-10-21', 'Erstgespräch',     50, 'Patientin nach Geburt erstes Kind leicht bis mittelgradig depressiv (PPD). Schuldgefühle, Erschöpfung, Freudlosigkeit. Partner einbezogen.'),
(20, 'Dr. Markus Vogel', '2025-11-04', 'Einzeltherapie',   50, 'Psychoedukation zur PPD. Entlastungsstrategien entwickelt. Patientin fühlt sich verstanden; Scham reduziert.'),

-- Patient 22 — Karin Krüger (F60.3 EUPD)
(22, 'Dr. Hanna Becker', '2025-08-12', 'Erstgespräch',     50, 'Patientin berichtet von instabilen Beziehungen, impulsiven Ausgaben, Selbstverletzung (Ritzen, zuletzt vor 3 Monaten). DBT empfohlen.'),
(22, 'Dr. Hanna Becker', '2025-08-26', 'Einzeltherapie',   50, 'Fertigkeitentraining: Achtsamkeit und TIPP. Keine akuten Selbstverletzungen. Krisenplan erstellt.'),
(22, 'Dr. Hanna Becker', '2025-09-09', 'Gruppentherapie',  90, 'DBT-Gruppe: Emotionsregulation. Patientin teilt Erfahrungen offen. Positive Dynamik in der Gruppe.'),

-- Patient 24 — Julia Hartmann (F43.1 PTSD)
(24, 'Dr. Klaus Wirth',  '2025-07-01', 'Erstgespräch',     50, 'Sexualisierte Gewalt im Jugendalter. Patientin hat lange geschwiegen, jetzt bereit für Therapie. Stabilisierungsphase.'),
(24, 'Dr. Klaus Wirth',  '2025-07-15', 'Einzeltherapie',   50, 'Ressourcen gestärkt. Patientin hat stützende Freundschaft gefunden. Keine akute Suizidalität.'),
(24, 'Dr. Klaus Wirth',  '2025-07-29', 'Einzeltherapie',   50, 'Erste traumanarrativische Arbeit. Patientin bricht Sitzung nach 30 Minuten ab — dissoziative Episode. Stabilisiert sich mit gegrundeten Techniken.'),
(24, 'Dr. Klaus Wirth',  '2025-08-12', 'Einzeltherapie',   50, 'Patientin berichtet von weniger Alpträumen. Schlaf etwas besser. Weiterarbeit am Traumanarrativ geplant.'),

-- Patient 26 — Birgit Schmitt (F41.1)
(26, 'Dr. Sabine Kohl',  '2025-10-09', 'Erstgespräch',     50, 'Langjährige Sorgenproblematik, nun verstärkt durch Pflege des Vaters. Erschöpfung, Reizbarkeit, Schlafstörungen. Erstdiagnose GAD.'),
(26, 'Dr. Sabine Kohl',  '2025-10-23', 'Einzeltherapie',   50, 'Grenzen setzen als zentrales Thema. Patientin übt Ablehnung von Hilfesanfragen. Fortschritt in Sitzung gut.'),

-- Patient 28 — Anja Schmitz (F50.0 anorexia)
(28, 'Dr. Markus Vogel', '2025-09-09', 'Erstgespräch',     50, 'Restriktives Essverhalten seit Teenagerjahren. BMI 17,4. Aktuell arbeitsfähig. Selbstwert stark an Figur geknüpft. Therapieziel: Normalisierung des Essverhaltens.'),
(28, 'Dr. Markus Vogel', '2025-09-23', 'Einzeltherapie',   50, 'Mahlzeitenprotokolle geführt. Schwierigkeit, drei Mahlzeiten täglich zu essen. Exposition mit Angstmahlzeit (Brot) begonnen.'),

-- Patient 30 — Laura Meier (F32.2)
(30, 'Dr. Hanna Becker', '2025-08-19', 'Erstgespräch',     50, 'Patientin (25 J.) nach Studienabbruch und Beziehungsende schwer depressiv. Passive Suizidgedanken. Sicherheitsabklärung OK. Engmaschige Anbindung.'),
(30, 'Dr. Hanna Becker', '2025-09-02', 'Einzeltherapie',   50, 'Leichte Aufhellung nach erster Sitzung. Strukturierter Tagesplan hilfreich. Kontakt zu Eltern wiederaufgenommen.'),
(30, 'Dr. Hanna Becker', '2025-09-16', 'Einzeltherapie',   50, 'Stimmung insgesamt besser. Patientin erwägt Ausbildung. Zukunftsperspektive entwickelt sich.'),

-- Patient 32 — Katharina Köhler (F41.0 panic disorder)
(32, 'Dr. Klaus Wirth',  '2025-09-18', 'Erstgespräch',     50, 'Panikattacken seit sechs Wochen, meist nachts. Patientin fürchtet Herzerkrankung (kardiales Clearing unauffällig). Psychoedukation.'),
(32, 'Dr. Klaus Wirth',  '2025-10-02', 'Einzeltherapie',   50, 'Atemtechnik (4-7-8) gut erlernt. Körperscan begonnen. Letzte Panikattacke weniger intensiv als vorherige.'),

-- Patient 34 — Franziska Walter (F60.3 EUPD)
(34, 'Dr. Sabine Kohl',  '2025-07-14', 'Erstgespräch',     50, 'Patientin mit langjähriger Borderline-Diagnose. Erste DBT-Behandlung vor zwei Jahren abgebrochen. Jetzt erneut motiviert. Niedrigere Sitzungsfrequenz vereinbart.'),
(34, 'Dr. Sabine Kohl',  '2025-07-28', 'Einzeltherapie',   50, 'Biosoziales Modell der BPS wiederholt. Patientin zeigt besseres Verständnis als beim ersten Mal. Stärke: hohe Intelligenz und Introspektion.'),
(34, 'Dr. Sabine Kohl',  '2025-08-11', 'Einzeltherapie',   50, 'Interpersonelle Effektivität: FAST-Fertigkeiten geübt. Patientin übt Nein-Sagen im Rollenspiel.'),

-- Patient 36 — Lena König (F43.1)
(36, 'Dr. Markus Vogel', '2025-10-28', 'Erstgespräch',     50, 'Mobbing am Arbeitsplatz über zwei Jahre. PTSD-Symptome: Intrusionen, Hypervigilanz, Rückzug. AU läuft. Stabilisierungsphase.'),

-- Patient 38 — Emma Fuchs (F40.1 social phobia)
(38, 'Dr. Hanna Becker', '2025-09-25', 'Erstgespräch',     50, 'Studentin, scheitert an mündlichen Prüfungen und Gruppenarbeiten durch Angst. Soziale Phobie seit Schulzeit. Exposition geplant.'),
(38, 'Dr. Hanna Becker', '2025-10-09', 'Einzeltherapie',   50, 'Angsthierarchie erstellt. Erste Exposition: im Seminar eine Frage stellen. Aufgabe erledigt — Angst 6/10 erwartet, 4/10 tatsächlich.'),

-- Patient 40 — Hannah Roth (F41.0)
(40, 'Dr. Klaus Wirth',  '2025-11-06', 'Erstgespräch',     50, 'Patientin nach Umzug in neue Stadt mit Panikattacken und Agoraphobie. Soziale Isolation verstärkt Symptome. Erklärungsmodell erläutert. Behandlungsplan erstellt.'),

-- Patient 41 — David Müller (F32.1)
(41, 'Dr. Sabine Kohl',  '2025-09-30', 'Erstgespräch',     50, 'Burnout-Symptomatik nach Jahren als Pflegekraft. Depressive Verstimmung, Erschöpfung, Zynismus. Berufliche Neuorientierung als Thema.'),
(41, 'Dr. Sabine Kohl',  '2025-10-14', 'Einzeltherapie',   50, 'Werte-Klärung durchgeführt. Patient erkennt Diskrepanz zwischen eigenen Werten und aktuellem Job. Perspektiven entwickelt.'),

-- Patient 44 — Lara Fischer (F41.1)
(44, 'Dr. Markus Vogel', '2025-08-28', 'Erstgespräch',     50, 'Patientin (27 J.) mit Examensangst und generalisierter Sorgenproblematik. Schlafstörungen. Erstdiagnose GAD. CBT begonnen.'),
(44, 'Dr. Markus Vogel', '2025-09-11', 'Einzeltherapie',   50, 'Sorgenaufschub-Technik eingeführt. Patientin berichtet von deutlich weniger nächtlichem Grübeln. Guter Fortschritt.'),

-- Patient 47 — Maximilian Wagner (F32.1)
(47, 'Dr. Hanna Becker', '2025-10-16', 'Erstgespräch',     50, 'Nach Vaterschaft (Zwillinge) depressiv. Erschöpfung, Versagensgefühle. Paternal Postpartum Depression. Partner-Einzel-Sitzung geplant.'),

-- Patient 49 — Johannes Schulz (F50.0)
(49, 'Dr. Klaus Wirth',  '2025-09-04', 'Erstgespräch',     50, 'Patient (56 J.) mit restriktivem Essen und orthorektischen Zügen. BMI 18,1. Kontrolle über Essen als Kompensation für Kontrollverlust in anderen Lebensbereichen.'),
(49, 'Dr. Klaus Wirth',  '2025-09-18', 'Einzeltherapie',   50, 'Kognitives Modell der Essstörung erarbeitet. Patient sehr reflektiert. Mahlzeitenflexibilisierung als Ziel.'),

-- Patient 54 — Melanie Richter (F40.1)
(54, 'Dr. Sabine Kohl',  '2025-10-02', 'Erstgespräch',     50, 'Soziale Phobie mit Schwerpunkt auf Arbeitssituation (Präsentationen, Meetings). Beförderung abgelehnt wegen Angst. Exposition geplant.'),
(54, 'Dr. Sabine Kohl',  '2025-10-16', 'Einzeltherapie',   50, 'Videobasiertes Feedback zu sozialem Verhalten: Patientin nimmt sich schlechter wahr als sie ist. Überzeugungsarbeit.'),

-- Patient 58 — Andreas Schwarz (F41.0)
(58, 'Dr. Markus Vogel', '2025-09-09', 'Erstgespräch',     50, 'Panikstörung mit agoraphober Vermeidung. Patient fährt seit 8 Monaten nicht mehr U-Bahn. Exposition strukturiert geplant.'),
(58, 'Dr. Markus Vogel', '2025-09-23', 'Einzeltherapie',   50, 'Expositionshierarchie erstellt. Erste Exposition: U-Bahnhof aufsuchen ohne einzusteigen. Erfolgreich.'),
(58, 'Dr. Markus Vogel', '2025-10-07', 'Einzeltherapie',   50, 'Patient ist eine Station U-Bahn gefahren. Angst 7/10, rasch abgeklungen. Sehr motiviert.'),

-- Patient 62 — Claudia Krüger (F32.1)
(62, 'Dr. Hanna Becker', '2025-10-23', 'Erstgespräch',     50, 'Depressive Episode nach Verlust des Bruders. Trauer vermischt mit Depression. Unterscheidung Trauer vs. Depression besprochen.'),
(62, 'Dr. Hanna Becker', '2025-11-06', 'Einzeltherapie',   50, 'Trauerarbeit: Brief an Bruder geschrieben. Patientin weint viel, aber erleichtert. Guter therapeutischer Kontakt.'),

-- Patient 64 — Nicole Hartmann (F40.1)
(64, 'Dr. Klaus Wirth',  '2025-09-16', 'Erstgespräch',     50, 'Soziale Phobie, hauptsächlich Angst vor Bewertung durch Kollegen. Perfektionismus als aufrechterhaltender Faktor.'),
(64, 'Dr. Klaus Wirth',  '2025-09-30', 'Einzeltherapie',   50, 'Perfektionismusmodul begonnen. Kosten-Nutzen-Analyse von Perfektionismus erstellt. Patientin überrascht von den Kosten.'),

-- Patient 66 — Sandra Schmitt (F50.0)
(66, 'Dr. Sabine Kohl',  '2025-08-07', 'Erstgespräch',     50, 'Patientin (27 J.) mit Binge-Eating-Störung. Essattacken 3–4x/Woche, danach starke Scham. BMI 28. Psychoedukation begonnen.'),
(66, 'Dr. Sabine Kohl',  '2025-08-21', 'Einzeltherapie',   50, 'Essprotokoll analysiert: Attacken meist abends und bei Einsamkeit. Alternativverhalten entwickelt.'),

-- Patient 70 — Monika Meier (F32.1)
(70, 'Dr. Markus Vogel', '2025-11-04', 'Erstgespräch',     50, 'Patientin nach Kündigung (betriebsbedingt) depressiv. Selbstwertprobleme, sozialer Rückzug. Ressourcendiagnostik durchgeführt.'),

-- Patient 72 — Stefanie Köhler (F43.1)
(72, 'Dr. Hanna Becker', '2025-09-02', 'Erstgespräch',     50, 'Häusliche Gewalt durch Ex-Partner vor einem Jahr. PTSD mit ausgeprägter Vermeidung (Stadtteile, Öffis). Sicherheitsplanung.'),
(72, 'Dr. Hanna Becker', '2025-09-16', 'Einzeltherapie',   50, 'EMDR-Vorbereitung (Safe Place gut etabliert). Patientin fühlt sich sicher in der Therapie.'),
(72, 'Dr. Hanna Becker', '2025-09-30', 'Einzeltherapie',   50, 'Erste EMDR-Sitzung. Zielgedächtnis aktiviert. SUD initial 9/10, nach Prozessierung auf 5/10. Fortschritt.'),

-- Patient 78 — Karin Fuchs (F32.2)
(78, 'Dr. Klaus Wirth',  '2025-07-08', 'Erstgespräch',     50, 'Schwere depressive Episode mit psychotischen Merkmalen (nihilistischer Wahn). Hospitalisierung vor drei Wochen abgeschlossen. Ambulante Nachbetreuung.'),
(78, 'Dr. Klaus Wirth',  '2025-07-22', 'Einzeltherapie',   50, 'Patientin deutlich stabilisiert, Wahngedanken remittiert. Psychoedukation zu Depression und Rückfallprophylaxe.'),
(78, 'Dr. Klaus Wirth',  '2025-08-05', 'Einzeltherapie',   50, 'Reintegration in Alltag. Teilzeitarbeit wieder aufgenommen. Stimmung im grünen Bereich. Sitzungsfrequenz reduziert.'),

-- Patient 80 — Julia Roth (F41.0)
(80, 'Dr. Sabine Kohl',  '2025-10-30', 'Erstgespräch',     50, 'Panikattacken im Straßenverkehr als Fahrerin. Patientin fährt kein Auto mehr seit drei Monaten. Einschränkungen im Alltag erheblich. Behandlungsplan erstellt.');
