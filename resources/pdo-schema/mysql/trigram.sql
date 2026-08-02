CREATE TABLE IF NOT EXISTS entry_attribute_trigrams (
    entry_lc_dn      VARCHAR(768) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    attr_name_lower  VARCHAR(255) NOT NULL,
    trigram          VARCHAR(3) NOT NULL,
    INDEX idx_trgm_attr (attr_name_lower, trigram),
    INDEX idx_trgm_entry (entry_lc_dn),
    CONSTRAINT fk_trgm_entry FOREIGN KEY (entry_lc_dn)
        REFERENCES entries(lc_dn) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
