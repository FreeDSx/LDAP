CREATE TABLE IF NOT EXISTS entry_attribute_trigrams (
    entry_lc_dn      TEXT NOT NULL,
    attr_name_lower  TEXT NOT NULL,
    trigram          TEXT NOT NULL,
    FOREIGN KEY (entry_lc_dn) REFERENCES entries(lc_dn) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_trgm_attr ON entry_attribute_trigrams (attr_name_lower, trigram);

CREATE INDEX IF NOT EXISTS idx_trgm_entry ON entry_attribute_trigrams (entry_lc_dn);
