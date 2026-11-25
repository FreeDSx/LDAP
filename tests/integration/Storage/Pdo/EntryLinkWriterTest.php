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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Pdo;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Writer\EntryLinkWriter;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Import\LdapImporter;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class EntryLinkWriterTest extends TestCase
{
    private const BASE = 'dc=example,dc=com';

    private const ADMINS = 'cn=Admins,dc=example,dc=com';

    private const BOB = 'cn=Bob,dc=example,dc=com';

    private const ALICE = 'cn=Alice,dc=example,dc=com';

    private EntryLinkWriter $subject;

    private WriteEntryInterface $storage;

    protected function setUp(): void
    {
        $container = Container::forServer(TestServerOptions::sqlite());
        $this->subject = $container->get(EntryLinkWriter::class);
        $this->storage = $container->get(WriteEntryInterface::class);

        $container->get(LdapImporter::class)->importEntries([
            Entry::fromArray(
                self::BASE,
                ['dc' => ['example']],
            ),
            Entry::fromArray(
                self::BOB,
                [
                    'objectClass' => ['person'],
                    'cn' => ['Bob'],
                    'sn' => ['Bob'],
                ],
            ),
            Entry::fromArray(
                self::ALICE,
                [
                    'objectClass' => ['person'],
                    'cn' => ['Alice'],
                    'sn' => ['Alice'],
                ],
            ),
            Entry::fromArray(
                self::ADMINS,
                [
                    'objectClass' => ['groupOfNames'],
                    'cn' => ['Admins'],
                    'member' => [self::BOB, self::ALICE],
                ],
            ),
        ]);
    }

    public function test_a_held_value_is_found_past_the_first_statement_of_values(): void
    {
        $asked = [];

        for ($i = 0; $i < 1200; $i++) {
            $asked[] = $i === 1100
                ? 'CN=Bob, DC=example, DC=com'
                : "cn=nobody{$i}," . self::BASE;
        }

        self::assertSame(
            ['CN=Bob, DC=example, DC=com'],
            $this->subject->heldLinkValues(
                new Dn(self::ADMINS),
                'member',
                $asked,
            ),
        );
    }

    public function test_a_renamed_target_is_held_under_its_new_dn_and_not_its_old_one(): void
    {
        $this->storage->renameSubtree(
            new Dn(self::BOB),
            new Dn('cn=Robert,' . self::BASE),
        );

        self::assertSame(
            [['cn=Robert,' . self::BASE], []],
            [
                $this->subject->heldLinkValues(
                    new Dn(self::ADMINS),
                    'member',
                    ['cn=Robert,' . self::BASE],
                ),
                $this->subject->heldLinkValues(
                    new Dn(self::ADMINS),
                    'member',
                    [self::BOB],
                ),
            ],
        );
    }

    public function test_every_value_the_owner_links_is_read(): void
    {
        self::assertEqualsCanonicalizing(
            [self::BOB, self::ALICE],
            $this->subject->linkValues(
                new Dn(self::ADMINS),
                'member',
            ),
        );
    }

    public function test_a_value_the_owner_does_not_link_is_not_held(): void
    {
        self::assertSame(
            [],
            $this->subject->heldLinkValues(
                new Dn(self::ADMINS),
                'member',
                ['cn=Carol,' . self::BASE],
            ),
        );
    }
}
