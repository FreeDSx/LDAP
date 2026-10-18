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
use FreeDSx\Ldap\Server\Backend\Storage\Import\LdapImporter;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class EntryLinkWriterTest extends TestCase
{
    private const BASE = 'dc=example,dc=com';

    private const ADMINS = 'cn=Admins,dc=example,dc=com';

    private const BOB = 'cn=Bob,dc=example,dc=com';

    private const CAROL = 'cn=Carol,dc=example,dc=com';

    private EntryLinkWriter $subject;

    protected function setUp(): void
    {
        $container = Container::forServer(TestServerOptions::sqlite());
        $this->subject = $container->get(EntryLinkWriter::class);

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
                self::CAROL,
                [
                    'objectClass' => ['person'],
                    'cn' => ['Carol'],
                    'sn' => ['Carol'],
                ],
            ),
            Entry::fromArray(
                self::ADMINS,
                [
                    'objectClass' => ['groupOfNames'],
                    'cn' => ['Admins'],
                    'member' => [self::BOB, self::CAROL],
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

    public function test_a_value_the_owner_does_not_link_is_not_held(): void
    {
        self::assertSame(
            [],
            $this->subject->heldLinkValues(
                new Dn(self::ADMINS),
                'member',
                ['cn=Dan,' . self::BASE],
            ),
        );
    }

    public function test_a_count_under_its_bound_is_every_value_linked(): void
    {
        self::assertSame(
            2,
            $this->subject->linkCount(
                new Dn(self::ADMINS),
                'member',
                5,
            ),
        );
    }

    public function test_a_count_stops_at_its_bound(): void
    {
        self::assertSame(
            1,
            $this->subject->linkCount(
                new Dn(self::ADMINS),
                'member',
                1,
            ),
        );
    }

    public function test_an_attribute_linking_nothing_counts_none(): void
    {
        self::assertSame(
            0,
            $this->subject->linkCount(
                new Dn(self::ADMINS),
                'seeAlso',
                5,
            ),
        );
    }
}
