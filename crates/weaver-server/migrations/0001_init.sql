CREATE TABLE config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    config_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE acme_account (
    directory TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    key_pem TEXT NOT NULL,
    kid TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE certificates (
    name TEXT PRIMARY KEY,
    cert_pem TEXT NOT NULL,
    key_pem TEXT NOT NULL,
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    issuer TEXT,
    directory TEXT NOT NULL,
    obtained_at INTEGER NOT NULL,
    last_active_at INTEGER
);

CREATE TABLE cert_events (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    at INTEGER NOT NULL,
    kind TEXT NOT NULL,
    detail TEXT
);
