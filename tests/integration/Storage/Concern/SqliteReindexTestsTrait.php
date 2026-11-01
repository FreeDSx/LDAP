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
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\InvalidDnSyntaxException;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Ldif\Loader\StringLdifLoader;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ListEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\DnKeyCollisionException;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use PDO;

/**
 * Reindex cases that reach past the storage contract into SQLite's own tables.
 */
trait SqliteReindexTestsTrait
{
    private const ACME = 'o=Acme™ Widgets,dc=foo,dc=bar';

    private const ACME_CHILD = 'cn=bob,o=Acme™ Widgets,dc=foo,dc=bar';

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

    public function test_reindex_rebuilds_dn_keys_written_in_an_older_form(): void
    {
        $this->withServer(function (
            LdapServer $server,
            Container $container,
        ): void {
            $reader = $container->get(ReadEntryInterface::class);
            $this->writeOlderDnKeys();
            self::assertNull($reader->find(new Dn(self::ACME)));

            $server->reindex();

            self::assertNotNull($reader->find(new Dn(self::ACME)));
            self::assertNotNull($reader->find(new Dn(self::ACME_CHILD)));
            self::assertSame(
                [self::ACME_CHILD],
                $this->childrenOf(
                    $container,
                    self::ACME,
                ),
            );
        });
    }

    public function test_reindex_resolves_a_reference_parked_under_a_dn_key_in_an_older_form(): void
    {
        $this->withServer(function (
            LdapServer $server,
            Container $container,
        ): void {
            $reader = $container->get(ReadEntryInterface::class);
            $this->parkMember(
                'cn=bob,o=acmeTM widgets,dc=foo,dc=bar',
                self::ACME_CHILD,
            );
            self::assertNotContains(
                self::ACME_CHILD,
                $this->membersOfAdmins($reader),
            );

            $server->reindex();

            self::assertContains(
                self::ACME_CHILD,
                $this->membersOfAdmins($reader),
            );
        });
    }

    public function test_reindex_links_an_entry_once_when_two_parked_references_now_share_its_key(): void
    {
        $this->withServer(function (
            LdapServer $server,
            Container $container,
        ): void {
            $this->writeOlderDnKeys();
            $this->parkMember(
                'o=acmetm widgets,dc=foo,dc=bar',
                'o=AcmeTM Widgets,dc=foo,dc=bar',
            );
            $this->parkMember(
                'o=acmeTm widgets,dc=foo,dc=bar',
                "o=Acme\u{1D413}M Widgets,dc=foo,dc=bar",
            );

            $server->reindex();

            self::assertSame(
                [
                    'cn=admin,dc=foo,dc=bar',
                    self::ACME,
                ],
                $this->membersOfAdmins($container->get(ReadEntryInterface::class)),
            );
        });
    }

    public function test_reindex_rebuilds_a_key_that_another_entry_held_in_an_older_form(): void
    {
        $this->withServer(function (
            LdapServer $server,
            Container $container,
        ): void {
            $reader = $container->get(ReadEntryInterface::class);
            $this->moveDnKey(
                'cn=street,dc=foo,dc=bar',
                'cn=stale,dc=foo,dc=bar',
            );
            $this->moveDnKey(
                'o=acmetm widgets,dc=foo,dc=bar',
                'cn=street,dc=foo,dc=bar',
            );

            $server->reindex();

            self::assertSame(
                self::ACME,
                $reader->find(new Dn(self::ACME))?->getDn()->toString(),
            );
            self::assertSame(
                'cn=street,dc=foo,dc=bar',
                $reader->find(new Dn('cn=street,dc=foo,dc=bar'))?->getDn()->toString(),
            );
        });
    }

    public function test_reindex_refuses_entries_whose_dns_now_share_a_key_and_changes_nothing(): void
    {
        $this->withServer(function (
            LdapServer $server,
            Container $container,
        ): void {
            $this->writeOlderDnKeys();
            $server->seed(new StringLdifLoader(<<<LDIF
                version: 1

                dn: o=AcmeTM Widgets,dc=foo,dc=bar
                objectClass: organization
                o: AcmeTM Widgets

                LDIF));
            $before = $this->dnsMatching(
                $container,
                Filters::present('objectClass'),
            );

            try {
                $server->reindex();
                self::fail('Entries sharing one DN key should have been refused.');
            } catch (DnKeyCollisionException $e) {
                self::assertStringContainsString(
                    'o=AcmeTM Widgets,dc=foo,dc=bar',
                    $e->getMessage(),
                );
            }

            self::assertSame(
                $before,
                $this->dnsMatching(
                    $container,
                    Filters::present('objectClass'),
                ),
            );
        });
    }

    public function test_reindex_names_a_stored_dn_that_no_longer_parses(): void
    {
        $this->withServer(function (LdapServer $server): void {
            $this->pdo()
                ->prepare('UPDATE entries SET dn = ? WHERE lc_dn = ?')
                ->execute([
                    'cn=#zz,dc=foo,dc=bar',
                    'cn=street,dc=foo,dc=bar',
                ]);

            $this->expectException(InvalidDnSyntaxException::class);
            $this->expectExceptionMessage('The stored DN "cn=#zz,dc=foo,dc=bar" is not valid');

            $server->reindex();
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

    /**
     * Rewrites the Acme DN keys the way they were stored before case was folded again after NFKC.
     */
    private function writeOlderDnKeys(): void
    {
        $this->pdo()->exec(<<<SQL
            UPDATE entries
            SET lc_dn = REPLACE(lc_dn, 'acmetm', 'acmeTM'),
                lc_parent_dn = REPLACE(lc_parent_dn, 'acmetm', 'acmeTM')
            SQL);
    }

    /**
     * Parks an unresolved member of the admins group under the given key.
     */
    private function parkMember(
        string $targetLcDn,
        string $value,
    ): void {
        $this->pdo()
            ->prepare(<<<SQL
                INSERT INTO entry_link_pending (owner_entry_id, attr_name_lower, target_lc_dn, target_value)
                SELECT entry_id, 'member', ?, ? FROM entries WHERE lc_dn = 'cn=admins,dc=foo,dc=bar'
                SQL)
            ->execute([
                $targetLcDn,
                $value,
            ]);
    }

    private function moveDnKey(
        string $from,
        string $to,
    ): void {
        $this->pdo()
            ->prepare('UPDATE entries SET lc_dn = ? WHERE lc_dn = ?')
            ->execute([
                $to,
                $from,
            ]);
    }

    /**
     * @return list<string>
     */
    private function membersOfAdmins(ReadEntryInterface $reader): array
    {
        return array_values(
            $reader->find(new Dn('cn=admins,dc=foo,dc=bar'))?->get('member')?->getValues() ?? [],
        );
    }

    /**
     * @return list<string>
     */
    private function childrenOf(
        Container $container,
        string $parent,
    ): array {
        $entries = $container->get(ListEntryInterface::class)->list(StorageListOptions::matchAll(
            new Dn($parent),
            subtree: false,
        ))->entries();

        $dns = [];
        foreach ($entries as $entry) {
            $dns[] = $entry->getDn()->toString();
        }

        return $dns;
    }

    private function pdo(): PDO
    {
        return new PDO('sqlite:' . $this->path);
    }
}
