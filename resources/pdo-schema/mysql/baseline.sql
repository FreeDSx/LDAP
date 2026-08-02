CREATE TABLE IF NOT EXISTS entries (
    lc_dn         VARCHAR(768) NOT NULL,
    dn            VARCHAR(768) NOT NULL,
    lc_parent_dn  VARCHAR(768) NOT NULL DEFAULT '',
    attributes    LONGBLOB NOT NULL,
    PRIMARY KEY (lc_dn),
    INDEX idx_lc_parent_dn (lc_parent_dn)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS entry_attribute_values (
    entry_lc_dn      VARCHAR(768) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    attr_name_lower  VARCHAR(255) NOT NULL,
    value_lower      VARCHAR(255) NOT NULL,
    value_original   TEXT NOT NULL,
    INDEX idx_eav_attr_value (attr_name_lower, value_lower),
    INDEX idx_eav_entry (entry_lc_dn),
    CONSTRAINT fk_eav_entry FOREIGN KEY (entry_lc_dn)
        REFERENCES entries(lc_dn) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS ldap_change_journal (
    seq          BIGINT NOT NULL,
    origin       VARCHAR(255) NOT NULL,
    created_at   BIGINT NOT NULL,
    change_type  VARCHAR(16) NOT NULL,
    dn           TEXT NOT NULL,
    lc_dn        VARCHAR(768) NOT NULL,
    lc_parent_dn VARCHAR(768) NOT NULL DEFAULT '',
    entry_uuid   VARCHAR(255) NOT NULL,
    authz_id     TEXT NOT NULL,
    previous_dn  TEXT,
    pre_image    LONGBLOB,
    PRIMARY KEY (seq),
    INDEX idx_journal_created_at (created_at),
    INDEX idx_journal_lc_dn (lc_dn),
    INDEX idx_journal_lc_parent_dn (lc_parent_dn)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ldap_change_journal_seq (
    id   INT NOT NULL,
    seq  BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO ldap_change_journal_seq (id, seq) VALUES (1, 0);

CREATE TABLE IF NOT EXISTS ldap_replica_pwpolicy_state (
    lc_dn          VARCHAR(768) NOT NULL,
    state          JSON NOT NULL,
    seq            BIGINT NOT NULL DEFAULT 0,
    forwarded_seq  BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (lc_dn),
    FOREIGN KEY (lc_dn) REFERENCES entries(lc_dn) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
