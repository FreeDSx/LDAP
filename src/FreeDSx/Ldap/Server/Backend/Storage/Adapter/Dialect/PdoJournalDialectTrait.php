<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect;

/**
 * Cross-platform change-journal SQL shared by every PdoJournalDialectInterface implementation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait PdoJournalDialectTrait
{
    public function queryJournalInsert(): string
    {
        return <<<SQL
            INSERT INTO ldap_change_journal
                (seq, origin, created_at, change_type, dn, lc_dn, lc_parent_dn, entry_uuid, authz_id, previous_dn, pre_image)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        SQL;
    }

    public function queryJournalSeqBump(): string
    {
        return <<<SQL
            UPDATE ldap_change_journal_seq
            SET seq = seq + 1
            WHERE id = 1
        SQL;
    }

    public function queryJournalSeqRead(): string
    {
        return <<<SQL
            SELECT seq
            FROM ldap_change_journal_seq
            WHERE id = 1
        SQL;
    }

    public function queryJournalReadSince(): string
    {
        return <<<SQL
            SELECT seq, origin, created_at, change_type, dn, entry_uuid, authz_id, previous_dn, pre_image
            FROM ldap_change_journal
            WHERE seq > ?
            ORDER BY seq ASC
        SQL;
    }

    public function queryJournalMinSeq(): string
    {
        return <<<SQL
            SELECT MIN(seq)
            FROM ldap_change_journal
        SQL;
    }

    public function queryJournalKeepFloor(): string
    {
        return <<<SQL
            SELECT seq
            FROM ldap_change_journal
            ORDER BY seq DESC
            LIMIT 1 OFFSET ?
        SQL;
    }

    public function queryJournalDeleteBelow(): string
    {
        return <<<SQL
            DELETE FROM ldap_change_journal
            WHERE seq < ?
        SQL;
    }

    public function queryJournalAgeKeepFloor(): string
    {
        return <<<SQL
            SELECT MIN(seq)
            FROM ldap_change_journal
            WHERE created_at >= ?
        SQL;
    }
}
