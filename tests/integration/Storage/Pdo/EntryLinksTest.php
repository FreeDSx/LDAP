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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\EntryLinks;
use FreeDSx\Ldap\Server\Backend\Storage\Import\LdapImporter;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class EntryLinksTest extends TestCase
{
    private const BASE = 'dc=example,dc=com';

    private const ADMINS = 'cn=Admins,dc=example,dc=com';

    private const STAFF = 'cn=Staff,dc=example,dc=com';

    private const ALICE = 'cn=Alice,dc=example,dc=com';

    private const BOB = 'cn=Bob,dc=example,dc=com';

    private EntryLinks $subject;

    protected function setUp(): void
    {
        $container = Container::forServer(TestServerOptions::sqlite());
        $this->subject = $container->get(EntryLinks::class);

        $container->get(LdapImporter::class)->importEntries([
            Entry::fromArray(
                self::BASE,
                ['dc' => ['example']],
            ),
            $this->person('Alice'),
            $this->person('Bob'),
            $this->group(
                'Admins',
                self::ALICE,
                self::BOB,
            ),
            $this->group(
                'Staff',
                self::BOB,
            ),
        ]);
    }

    public function test_every_value_a_linked_attribute_holds_is_read(): void
    {
        self::assertEqualsCanonicalizing(
            [self::ALICE, self::BOB],
            $this->subject->linkValues(
                new Dn(self::ADMINS),
                'member',
            ),
        );
    }

    public function test_every_entry_naming_a_backlink_is_read(): void
    {
        self::assertEqualsCanonicalizing(
            [self::ADMINS, self::STAFF],
            $this->subject->linkValues(
                new Dn('CN=Bob, DC=example, DC=com'),
                'memberOf',
            ),
        );
    }

    public function test_an_entry_named_by_no_link_reads_no_backlink(): void
    {
        self::assertSame(
            [],
            $this->subject->linkValues(
                new Dn(self::BASE),
                'memberOf',
            ),
        );
    }

    private function person(string $name): Entry
    {
        return Entry::fromArray(
            "cn={$name}," . self::BASE,
            [
                'objectClass' => ['person'],
                'cn' => [$name],
                'sn' => [$name],
            ],
        );
    }

    private function group(
        string $name,
        string ...$members,
    ): Entry {
        return Entry::fromArray(
            "cn={$name}," . self::BASE,
            [
                'objectClass' => ['groupOfNames'],
                'cn' => [$name],
                'member' => $members,
            ],
        );
    }
}
