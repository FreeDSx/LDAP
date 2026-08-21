CREATE TABLE IF NOT EXISTS entries (
    entry_id      INTEGER PRIMARY KEY,
    lc_dn         TEXT NOT NULL UNIQUE,
    dn            TEXT NOT NULL,
    lc_parent_dn  TEXT NOT NULL DEFAULT '',
    attributes    BLOB NOT NULL DEFAULT 'a:0:{}'
);

CREATE INDEX IF NOT EXISTS idx_lc_parent_dn ON entries (lc_parent_dn);

-- Named apart from entries.entry_id so the correlated filter and sort SQL cannot bind to the inner scope.
CREATE TABLE IF NOT EXISTS entry_attribute_values (
    owner_entry_id   INTEGER NOT NULL,
    attr_name_lower  TEXT NOT NULL,
    value_lower      TEXT NOT NULL,
    value_original   TEXT NOT NULL,
    FOREIGN KEY (owner_entry_id) REFERENCES entries(entry_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_eav_attr_value ON entry_attribute_values (attr_name_lower, value_lower);

-- Covering (owner_entry_id leads): entry-scoped lookups plus index-only sort MIN() and correlated EXISTS.
CREATE INDEX IF NOT EXISTS idx_eav_entry ON entry_attribute_values (owner_entry_id, attr_name_lower, value_lower);

CREATE TABLE IF NOT EXISTS ldap_change_journal (
    seq          INTEGER NOT NULL PRIMARY KEY,
    origin       TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    change_type  TEXT NOT NULL,
    dn           TEXT NOT NULL,
    lc_dn        TEXT NOT NULL,
    lc_parent_dn TEXT NOT NULL DEFAULT '',
    entry_uuid   TEXT NOT NULL,
    authz_id     TEXT NOT NULL,
    previous_dn  TEXT,
    pre_image    BLOB
);

CREATE INDEX IF NOT EXISTS idx_journal_created_at ON ldap_change_journal (created_at);

CREATE INDEX IF NOT EXISTS idx_journal_lc_dn ON ldap_change_journal (lc_dn);

CREATE INDEX IF NOT EXISTS idx_journal_lc_parent_dn ON ldap_change_journal (lc_parent_dn);

CREATE TABLE IF NOT EXISTS ldap_change_journal_seq (
    id   INTEGER NOT NULL PRIMARY KEY,
    seq  INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO ldap_change_journal_seq (id, seq) VALUES (1, 0);

-- Keyed by entry_id so parent and DN changes are seamless.
CREATE TABLE IF NOT EXISTS ldap_replica_pwpolicy_state (
    entry_id       INTEGER NOT NULL PRIMARY KEY,
    state          TEXT NOT NULL,
    seq            INTEGER NOT NULL DEFAULT 0,
    forwarded_seq  INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (entry_id) REFERENCES entries(entry_id) ON DELETE CASCADE
);

-- Stamped from PdoStorage::SCHEMA_VERSION on connect, so a database states which schema it holds.
CREATE TABLE IF NOT EXISTS ldap_schema_version (
    id       INTEGER NOT NULL PRIMARY KEY,
    version  INTEGER NOT NULL
);
