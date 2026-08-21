-- Named apart from entries.entry_id so the correlated filter SQL cannot bind to the inner scope.
CREATE TABLE IF NOT EXISTS entry_attribute_trigrams (
    owner_entry_id   BIGINT NOT NULL,
    attr_name_lower  VARCHAR(255) NOT NULL,
    trigram          VARCHAR(3) NOT NULL,
    INDEX idx_trgm_attr (attr_name_lower, trigram),
    INDEX idx_trgm_entry (owner_entry_id),
    CONSTRAINT fk_trgm_entry FOREIGN KEY (owner_entry_id)
        REFERENCES entries(entry_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
