-- Named apart from entries.entry_id so the correlated filter SQL cannot bind to the inner scope.
CREATE TABLE IF NOT EXISTS entry_attribute_trigrams (
    owner_entry_id   INTEGER NOT NULL,
    attr_name_lower  TEXT NOT NULL,
    trigram          TEXT NOT NULL,
    FOREIGN KEY (owner_entry_id) REFERENCES entries(entry_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_trgm_attr ON entry_attribute_trigrams (attr_name_lower, trigram);

CREATE INDEX IF NOT EXISTS idx_trgm_entry ON entry_attribute_trigrams (owner_entry_id);
