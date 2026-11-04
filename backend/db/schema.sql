-- Cybersecurity Alert Summarizer - SQLite schema (plain SQL, no ORM).
-- One ANALYSIS = one uploaded file. It owns alerts, incidents, entities and Q&A logs.
-- Every child row references its parent with ON DELETE CASCADE, so deleting an analysis
-- removes everything that belongs to it.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS analyses (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    filename               TEXT    NOT NULL,
    uploaded_at            TEXT    NOT NULL,              -- ISO timestamp (UTC)
    finished_at            TEXT,
    status                 TEXT    NOT NULL DEFAULT 'processing'
                                   CHECK (status IN ('processing', 'done', 'failed')),
    error                  TEXT,
    n_alerts               INTEGER,
    n_alert_types          INTEGER,
    n_incidents            INTEGER,
    n_high                 INTEGER,                       -- incidents rated High or Critical
    perplexity_smoothed    REAL,                          -- held-out bigram perplexity, Laplace
    perplexity_unsmoothed  TEXT,                          -- may be 'infinity', so stored as text
    scenario               TEXT,                          -- detected AIT-ADS scenario (or NULL)
    insights_json          TEXT                           -- corpus-level NLP outputs for the NLP Lab
);

CREATE TABLE IF NOT EXISTS incidents (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id          INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    title                TEXT    NOT NULL,
    keywords             TEXT,                            -- top TF-IDF words of the cluster
    severity             TEXT    CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    severity_score       INTEGER,
    start_time           TEXT,
    end_time             TEXT,
    n_alerts             INTEGER,
    summary_template     TEXT,                            -- main summary (template filling)
    summary_extractive   TEXT,                            -- TF-IDF extractive baseline
    summary_abstractive  TEXT,                            -- pretrained model, filled on demand
    recommended_action   TEXT,
    slots_json           TEXT                             -- the filled template slots
);

CREATE TABLE IF NOT EXISTS alerts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id    INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    incident_id    INTEGER REFERENCES incidents(id) ON DELETE CASCADE,
    timestamp      TEXT    NOT NULL,
    source         TEXT    CHECK (source IN ('wazuh', 'suricata')),
    description    TEXT    NOT NULL,
    sentence       TEXT    NOT NULL,                      -- alert rendered as English (NLP corpus)
    level          INTEGER,
    src_ip         TEXT,
    dst_ip         TEXT,
    dst_port       INTEGER,
    host           TEXT,
    user           TEXT,
    mitre_id       TEXT,
    mitre_tactic   TEXT,
    url            TEXT,
    alert_type     TEXT,                                  -- merged type (edit distance)
    rarity_score   REAL,                                  -- bigram LM perplexity of the sentence
    cluster        INTEGER,                               -- TF-IDF KMeans cluster
    phase          TEXT,                                  -- attack phase (temporal analysis)
    triple_actor   TEXT,                                  -- dependency triple
    triple_action  TEXT,                                  -- action verb (WordNet-normalised)
    triple_target  TEXT
);

CREATE TABLE IF NOT EXISTS entities (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id  INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    alert_id     INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    text         TEXT    NOT NULL,
    label        TEXT    NOT NULL                         -- IP, PORT, HOST, USER, CVE, ...
);

CREATE TABLE IF NOT EXISTS relations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id  INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    subject      TEXT    NOT NULL,
    relation     TEXT    NOT NULL,                        -- ATTACKED, SCANNED, LOGGED_INTO, ...
    object       TEXT    NOT NULL,
    count        INTEGER NOT NULL DEFAULT 1               -- how many alerts support it
);

CREATE TABLE IF NOT EXISTS qa_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id  INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    question     TEXT    NOT NULL,
    answer       TEXT    NOT NULL,
    asked_at     TEXT    NOT NULL
);

-- Indexes on foreign keys / common filters (SQLite does not create them automatically).
CREATE INDEX IF NOT EXISTS idx_alerts_analysis   ON alerts(analysis_id);
CREATE INDEX IF NOT EXISTS idx_alerts_incident   ON alerts(incident_id);
CREATE INDEX IF NOT EXISTS idx_alerts_time       ON alerts(analysis_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_incidents_analysis ON incidents(analysis_id);
CREATE INDEX IF NOT EXISTS idx_entities_analysis ON entities(analysis_id, label);
CREATE INDEX IF NOT EXISTS idx_entities_alert    ON entities(alert_id);
CREATE INDEX IF NOT EXISTS idx_relations_incident ON relations(incident_id);
CREATE INDEX IF NOT EXISTS idx_qa_analysis       ON qa_logs(analysis_id);
