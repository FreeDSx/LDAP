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

namespace Tests\Integration\FreeDSx\Ldap\Ldif;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\Ldif\LdifChanges;
use FreeDSx\Ldap\Ldif\Loader\FileLdifLoader;
use FreeDSx\Ldap\Ldif\Loader\StringLdifLoader;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

final class LdapDumpServerTest extends ServerTestCase
{
    private const SEED_LDIF = __DIR__ . '/../../resources/seed/seed-test.ldif';

    private static string $dumpPath;

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        self::$dumpPath = sys_get_temp_dir() . '/freedsx-ldap-dump-integration.ldif';

        if (!extension_loaded('pcntl')) {
            return;
        }

        if (file_exists(self::$dumpPath)) {
            unlink(self::$dumpPath);
        }

        static::initSharedServer(
            'ldap-server',
            'tcp',
            [
                '--storage=sqlite',
                '--seed=' . self::SEED_LDIF,
                '--dump=' . self::$dumpPath,
            ],
        );
    }

    public static function tearDownAfterClass(): void
    {
        parent::tearDownAfterClass();
        static::tearDownSharedServer();

        if (file_exists(self::$dumpPath)) {
            unlink(self::$dumpPath);
        }
    }

    public function setUp(): void
    {
        $this->setServerMode('ldap-server');

        parent::setUp();
    }

    public function test_the_dump_file_was_written_and_starts_with_the_version_header(): void
    {
        self::assertFileExists(self::$dumpPath);
        $contents = (string) file_get_contents(self::$dumpPath);
        self::assertStringStartsWith(
            'version: 1',
            $contents,
        );
    }

    public function test_the_dump_file_parses_into_the_seeded_entries(): void
    {
        $parsed = LdifChanges::fromLoader(new FileLdifLoader(self::$dumpPath));

        $dns = [];
        foreach ($parsed->entries() as $entry) {
            $dns[] = $entry->getDn()->toString();
        }

        self::assertContains(
            'dc=foo,dc=bar',
            $dns,
        );
        self::assertContains(
            'cn=user,dc=foo,dc=bar',
            $dns,
        );
        self::assertContains(
            'cn=alice,dc=foo,dc=bar',
            $dns,
        );
        self::assertContains(
            'cn=bob,dc=foo,dc=bar',
            $dns,
        );
    }

    public function test_a_fresh_server_seeded_from_the_dump_reconstructs_the_directory(): void
    {
        $options = new ServerOptions();
        $container = Container::forServer($options);
        (new LdapServer(
            $options,
            $container,
        ))->seed(new StringLdifLoader((string) file_get_contents(self::$dumpPath)));
        $storage = $container->get(EntryStorageInterface::class);

        $alice = $storage->find(new Dn('cn=alice,dc=foo,dc=bar'));
        self::assertNotNull($alice);
        self::assertSame(
            ['Anderson'],
            $alice->get('sn')?->getValues(),
        );

        $bob = $storage->find(new Dn('cn=bob,dc=foo,dc=bar'));
        self::assertNotNull($bob);
        self::assertSame(
            ['Builder'],
            $bob->get('sn')?->getValues(),
        );
    }

    public function test_the_dump_preserves_operational_attributes_for_round_trip(): void
    {
        $parsed = LdifChanges::fromLoader(new FileLdifLoader(self::$dumpPath));

        $alice = null;
        foreach ($parsed->entries() as $entry) {
            if ($entry->getDn()->toString() === 'cn=alice,dc=foo,dc=bar') {
                $alice = $entry;
                break;
            }
        }

        self::assertNotNull($alice);
        self::assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/',
            $alice->get('entryUUID')?->firstValue() ?? '',
        );
        self::assertMatchesRegularExpression(
            '/^\d{14}Z$/',
            $alice->get('createTimestamp')?->firstValue() ?? '',
        );
    }
}
