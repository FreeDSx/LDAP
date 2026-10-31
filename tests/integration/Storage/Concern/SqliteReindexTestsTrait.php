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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Concern;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Search\Filters;
use PDO;

/**
 * Reindex cases that reach past the storage contract into SQLite's own tables.
 */
trait SqliteReindexTestsTrait
{
    /**
     * A directory written before a matching rule changed holds its index keys in the old form until it is reindexed.
     */
    public function test_reindex_restores_matching_for_keys_written_in_an_older_form(): void
    {
        $this->withServer(function (LdapServer $server, Container $container): void {
            // Equality folds the repeated spaces away, so the stored key is not what a plain case fold would write.
            $assertion = Filters::equal('description', 'Group Of Admins');
            self::assertCount(
                1,
                $this->dnsMatching($container, $assertion),
            );

            $this->writeStaleKey();
            self::assertCount(
                0,
                $this->dnsMatching($container, $assertion),
            );

            $server->reindex();
            self::assertCount(
                1,
                $this->dnsMatching($container, $assertion),
            );
        });
    }

    /**
     * The case of a directory that grew before substring indexing was enabled.
     */
    public function test_reindex_repopulates_the_substring_index(): void
    {
        $this->withServer(function (LdapServer $server): void {
            $this->pdo()->exec('DELETE FROM entry_attribute_trigrams');

            $server->reindex();

            $count = $this->pdo()->query('SELECT COUNT(*) FROM entry_attribute_trigrams');
            self::assertNotFalse($count);
            self::assertGreaterThan(
                0,
                (int) $count->fetchColumn(),
            );
        });
    }

    public function test_reindex_rewrites_the_substring_index_in_the_prepared_form(): void
    {
        $this->withServer(function (
            LdapServer $server,
            Container $container,
        ): void {
            $assertion = Filters::contains(
                'sn',
                'strasse',
            );
            self::assertCount(
                1,
                $this->dnsMatching(
                    $container,
                    $assertion,
                ),
            );

            $this->writeUnpreparedTrigrams();
            self::assertCount(
                0,
                $this->dnsMatching(
                    $container,
                    $assertion,
                ),
            );

            $server->reindex();
            self::assertCount(
                1,
                $this->dnsMatching(
                    $container,
                    $assertion,
                ),
            );
        });
    }

    /**
     * Rewrites the sn trigrams the way an index over plainly lowercased values would have held them.
     */
    private function writeUnpreparedTrigrams(): void
    {
        $pdo = $this->pdo();
        $pdo->exec("DELETE FROM entry_attribute_trigrams WHERE attr_name_lower = 'sn'");
        $insert = $pdo->prepare(<<<SQL
            INSERT INTO entry_attribute_trigrams (owner_entry_id, attr_name_lower, trigram)
            SELECT owner_entry_id, attr_name_lower, ?
            FROM entry_attribute_values
            WHERE attr_name_lower = 'sn' AND value_lower = 'strasse'
            SQL);

        foreach (['str', 'tra', 'raß', 'aße'] as $trigram) {
            $insert->execute([$trigram]);
        }
    }

    /**
     * Rewrites the sidecar the way a store keying by a plain case-folded profile would have.
     */
    private function writeStaleKey(): void
    {
        $this->pdo()
            ->prepare('UPDATE entry_attribute_values SET value_lower = ? WHERE attr_name_lower = ?')
            ->execute([
                'group  of  admins',
                'description',
            ]);
    }

    private function pdo(): PDO
    {
        return new PDO('sqlite:' . $this->path);
    }
}
