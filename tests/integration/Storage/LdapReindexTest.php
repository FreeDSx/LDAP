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

namespace Tests\Integration\FreeDSx\Ldap\Storage;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Ldif\Loader\StringLdifLoader;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\Config\Storage\SubstringIndexMode;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use PDO;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\TestWorker;

final class LdapReindexTest extends TestCase
{
    private const SEED = <<<LDIF
        version: 1

        dn: dc=foo,dc=bar
        objectClass: domain
        dc: foo

        dn: cn=admins,dc=foo,dc=bar
        objectClass: groupOfNames
        cn: admins
        member: CN=Admin, DC=Foo, DC=Bar

        LDIF;

    private string $path;

    private EntryStorageInterface $storage;

    private LdapServer $server;

    protected function setUp(): void
    {
        $this->path = TestWorker::path('reindex-integration.sqlite');
        $this->removeDatabase();

        // Pinned rather than auto-resolved, so the substring index under test is the same on every build.
        $options = (TestServerOptions::defaults())
            ->setStorageConfig(
                PdoConfig::forSqlite($this->path)
                    ->setSubstringIndexMode(SubstringIndexMode::Trigram),
            );
        $container = Container::forServer($options);

        $this->server = new LdapServer($options, $container);
        $this->server->seed(new StringLdifLoader(self::SEED));
        $this->storage = $container->get(EntryStorageInterface::class);
    }

    protected function tearDown(): void
    {
        $this->removeDatabase();
    }

    /**
     * A directory written before a matching rule changed holds its index keys in the old form until it is reindexed.
     */
    public function test_reindex_restores_matching_for_keys_written_in_an_older_form(): void
    {
        $assertion = Filters::equal('member', 'cn=admin,dc=foo,dc=bar');
        self::assertCount(
            1,
            $this->dnsMatching($assertion),
        );

        $this->writeStaleKey();
        self::assertCount(
            0,
            $this->dnsMatching($assertion),
        );

        $this->server->reindex();
        self::assertCount(
            1,
            $this->dnsMatching($assertion),
        );
    }

    /**
     * The case of a directory that grew before substring indexing was enabled.
     */
    public function test_reindex_repopulates_the_substring_index(): void
    {
        $pdo = new PDO('sqlite:' . $this->path);
        $pdo->exec('DELETE FROM entry_attribute_trigrams');

        $this->server->reindex();

        $count = $pdo->query('SELECT COUNT(*) FROM entry_attribute_trigrams');
        self::assertNotFalse($count);
        self::assertGreaterThan(
            0,
            (int) $count->fetchColumn(),
        );
    }

    public function test_reindex_preserves_entry_attributes(): void
    {
        $dn = new Dn('cn=admins,dc=foo,dc=bar');
        $before = $this->storage->find($dn);
        self::assertNotNull($before);

        $this->server->reindex();

        $after = $this->storage->find($dn);
        self::assertNotNull($after);
        self::assertEquals(
            $before->toArray(),
            $after->toArray(),
        );
    }

    /**
     * Rewrites the sidecar the way a store keying by a plain case-folded profile would have.
     */
    private function writeStaleKey(): void
    {
        $pdo = new PDO('sqlite:' . $this->path);
        $pdo->prepare('UPDATE entry_attribute_values SET value_lower = ? WHERE attr_name_lower = ?')
            ->execute([
                'cn=admin, dc=foo, dc=bar',
                'member',
            ]);
    }

    /**
     * @return list<string>
     */
    private function dnsMatching(FilterInterface $filter): array
    {
        $entries = $this->storage->list(new StorageListOptions(
            baseDn: new Dn('dc=foo,dc=bar'),
            subtree: true,
            filter: $filter,
        ))->entries;

        $dns = [];
        foreach ($entries as $entry) {
            $dns[] = $entry->getDn()->toString();
        }

        return $dns;
    }

    private function removeDatabase(): void
    {
        foreach (['', '-wal', '-shm'] as $suffix) {
            $file = $this->path . $suffix;
            if (file_exists($file)) {
                unlink($file);
            }
        }
    }
}
