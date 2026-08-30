CREATE TABLE IF NOT EXISTS entries (
    entry_id      BIGINT NOT NULL AUTO_INCREMENT,
    lc_dn         VARCHAR(768) COLLATE utf8mb4_bin NOT NULL,
    dn            VARCHAR(768) COLLATE utf8mb4_bin NOT NULL,
    lc_parent_dn  VARCHAR(768) COLLATE utf8mb4_bin NOT NULL DEFAULT '',
    attributes    LONGBLOB NOT NULL,
    PRIMARY KEY (entry_id),
    UNIQUE KEY uq_lc_dn (lc_dn),
    INDEX idx_lc_parent_dn (lc_parent_dn)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Named apart from entries.entry_id so the correlated filter and sort SQL cannot bind to the inner scope.
CREATE TABLE IF NOT EXISTS entry_attribute_values (
    owner_entry_id   BIGINT NOT NULL,
    attr_name_lower  VARCHAR(255) NOT NULL,
    value_lower      VARCHAR(255) NOT NULL,
    value_original   TEXT NOT NULL,
    INDEX idx_eav_attr_value (attr_name_lower, value_lower),
    -- Covering: an integer key leaves room under the 3072 byte limit a DN key does not.
    INDEX idx_eav_entry (owner_entry_id, attr_name_lower, value_lower),
    CONSTRAINT fk_eav_entry FOREIGN KEY (owner_entry_id)
        REFERENCES entries(entry_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS ldap_change_journal (
    seq          BIGINT NOT NULL,
    origin       VARCHAR(255) NOT NULL,
    created_at   BIGINT NOT NULL,
    change_type  VARCHAR(16) NOT NULL,
    dn           TEXT COLLATE utf8mb4_bin NOT NULL,
    lc_dn        VARCHAR(768) COLLATE utf8mb4_bin NOT NULL,
    lc_parent_dn VARCHAR(768) COLLATE utf8mb4_bin NOT NULL DEFAULT '',
    entry_uuid   VARCHAR(255) NOT NULL,
    authz_id     TEXT NOT NULL,
    previous_dn  TEXT COLLATE utf8mb4_bin,
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

-- Keyed by entry_id so parent and DN changes are seamless.
CREATE TABLE IF NOT EXISTS ldap_replica_pwpolicy_state (
    entry_id       BIGINT NOT NULL,
    state          JSON NOT NULL,
    seq            BIGINT NOT NULL DEFAULT 0,
    forwarded_seq  BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (entry_id),
    FOREIGN KEY (entry_id) REFERENCES entries(entry_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Stamped from PdoStorage::SCHEMA_VERSION on connect, so a database states which schema it holds.
CREATE TABLE IF NOT EXISTS ldap_schema_version (
    id       INT NOT NULL,
    version  INT NOT NULL,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
