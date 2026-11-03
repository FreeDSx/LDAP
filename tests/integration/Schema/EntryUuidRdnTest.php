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

namespace Tests\Integration\FreeDSx\Ldap\Schema;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\RecordRefusedException;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Ldif\Loader\StringLdifLoader;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use PDO;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\RequiresOperatingSystemTrait;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\TestWorker;

use function file_exists;
use function is_string;
use function unlink;

final class EntryUuidRdnTest extends TestCase
{
    use RequiresOperatingSystemTrait;

    private const NAMED_DN = 'cn=named,dc=foo,dc=bar';

    private string $path;

    private LdapServer $server;

    private Container $container;

    private string $uuid;

    protected function setUp(): void
    {
        $this->requireUnix('Windows cannot delete the SQLite files the in-process server still holds open.');

        $this->path = TestWorker::path('entry-uuid-rdn.sqlite');
        $this->removeDatabase();

        $options = TestServerOptions::defaults()->setStorageConfig(PdoConfig::forSqlite($this->path));
        $this->container = Container::forServer($options);
        $this->server = new LdapServer(
            $options,
            $this->container,
        );
        $this->server->seed(new StringLdifLoader(<<<LDIF
            version: 1

            dn: dc=foo,dc=bar
            objectClass: domain
            dc: foo

            dn: cn=named,dc=foo,dc=bar
            objectClass: device
            cn: named

            LDIF));
        $this->uuid = $this->nameByItsEntryUuid();
    }

    protected function tearDown(): void
    {
        $this->removeDatabase();
    }

    public function test_renaming_away_from_an_entry_uuid_rdn_while_deleting_the_old_rdn_is_refused(): void
    {
        try {
            $this->renameTo(
                'cn=freed',
                deleteOldRdn: true,
            );
            self::fail('A rename dropping the entryUUID should have been refused.');
        } catch (RecordRefusedException $e) {
            self::assertSame(
                ResultCode::CONSTRAINT_VIOLATION,
                $e->getCode(),
            );
        }
    }

    public function test_renaming_away_from_an_entry_uuid_rdn_while_keeping_the_old_rdn_succeeds(): void
    {
        $this->renameTo(
            'cn=freed',
            deleteOldRdn: false,
        );

        self::assertSame(
            [$this->uuid],
            $this->container
                ->get(ReadEntryInterface::class)
                ->find(new Dn('cn=freed,dc=foo,dc=bar'))
                ?->get('entryUUID')
                ?->getValues(),
        );
    }

    /**
     * Names the entry by its entryUUID in storage directly, a state no write can reach any more.
     */
    private function nameByItsEntryUuid(): string
    {
        $pdo = new PDO('sqlite:' . $this->path);
        $select = $pdo->prepare('SELECT entry_uuid FROM entries WHERE lc_dn = ?');
        $select->execute([self::NAMED_DN]);
        $uuid = $select->fetchColumn();
        self::assertTrue(is_string($uuid));

        $pdo->prepare('UPDATE entries SET dn = ?, lc_dn = ? WHERE lc_dn = ?')->execute([
            'entryUUID=' . $uuid . ',dc=foo,dc=bar',
            'entryuuid=' . $uuid . ',dc=foo,dc=bar',
            self::NAMED_DN,
        ]);

        return $uuid;
    }

    private function renameTo(
        string $newRdn,
        bool $deleteOldRdn,
    ): void {
        $deleteOld = $deleteOldRdn ? '1' : '0';

        $this->server->applyChanges(new StringLdifLoader(<<<LDIF
            version: 1

            dn: entryUUID={$this->uuid},dc=foo,dc=bar
            changetype: modrdn
            newrdn: {$newRdn}
            deleteoldrdn: {$deleteOld}

            LDIF));
    }

    private function removeDatabase(): void
    {
        // Teardown still runs when setUp skipped before naming a database.
        if (!isset($this->path)) {
            return;
        }

        foreach (['', '-wal', '-shm'] as $suffix) {
            if (file_exists($this->path . $suffix)) {
                unlink($this->path . $suffix);
            }
        }
    }
}
