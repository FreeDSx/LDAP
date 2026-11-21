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
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Writer\DeferredLinkWriter;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Writer\EntryLinkWriter;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkDelta;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use FreeDSx\Ldap\Server\Utility\Uuid;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

use function array_values;

final class DeferredLinkWriterTest extends TestCase
{
    private const UUID_TEAM = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

    private const UUID_CREW = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

    private const UUID_STAFF = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';

    private WriteEntryInterface $writer;

    private ReadEntryInterface $reader;

    private DeferredLinkWriter $subject;

    protected function setUp(): void
    {
        $container = Container::forServer(TestServerOptions::sqlite());
        $this->writer = $container->get(WriteEntryInterface::class);
        $this->reader = $container->get(ReadEntryInterface::class);
        $this->subject = new DeferredLinkWriter(
            $container->get(PdoDialectInterface::class),
            $container->get(PdoConnection::class),
            $container->get(LinkedAttributes::class),
            $container->get(EntryLinkWriter::class),
            valuesPerBatch: 3,
            ownersPerBatch: 2,
        );
    }

    public function test_values_held_back_for_an_entry_the_write_did_not_store_are_refused(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The entry "cn=team,dc=example,dc=com" has no storage key.');

        $this->subject->deferLinks(
            self::UUID_TEAM,
            new Entry(
                'cn=team,dc=example,dc=com',
                new Attribute('cn', 'team'),
                new Attribute('member', 'cn=alice,dc=example,dc=com'),
            ),
            static function (): void {},
        );
    }

    public function test_a_batch_stops_before_the_entry_whose_held_values_would_pass_its_cap(): void
    {
        $this->person('alice');
        $this->person('bob');
        $this->person('carol');
        $this->hold(
            'team',
            self::UUID_TEAM,
            'cn=alice,dc=example,dc=com',
        );
        $this->hold(
            'crew',
            self::UUID_CREW,
            'cn=alice,dc=example,dc=com',
            'cn=bob,dc=example,dc=com',
            'cn=carol,dc=example,dc=com',
        );

        $this->subject->linkDeferred();

        self::assertSame(
            ['cn=alice,dc=example,dc=com'],
            $this->members('cn=team,dc=example,dc=com'),
        );
        self::assertSame(
            [],
            $this->members('cn=crew,dc=example,dc=com'),
        );
    }

    public function test_a_batch_takes_every_entry_whose_held_values_together_reach_its_cap(): void
    {
        $this->person('alice');
        $this->person('bob');
        $this->hold(
            'team',
            self::UUID_TEAM,
            'cn=alice,dc=example,dc=com',
        );
        $this->hold(
            'crew',
            self::UUID_CREW,
            'cn=alice,dc=example,dc=com',
            'cn=bob,dc=example,dc=com',
        );

        $this->subject->linkDeferred();

        self::assertSame(
            ['cn=alice,dc=example,dc=com'],
            $this->members('cn=team,dc=example,dc=com'),
        );
        self::assertSame(
            [
                'cn=alice,dc=example,dc=com',
                'cn=bob,dc=example,dc=com',
            ],
            $this->members('cn=crew,dc=example,dc=com'),
        );
    }

    public function test_a_batch_stops_at_its_number_of_entries_whatever_values_they_hold(): void
    {
        $this->person('alice');
        $this->hold(
            'team',
            self::UUID_TEAM,
            'cn=alice,dc=example,dc=com',
        );
        $this->hold(
            'crew',
            self::UUID_CREW,
            'cn=alice,dc=example,dc=com',
        );
        $this->hold(
            'staff',
            self::UUID_STAFF,
            'cn=alice,dc=example,dc=com',
        );

        $this->subject->linkDeferred();

        self::assertSame(
            ['cn=alice,dc=example,dc=com'],
            $this->members('cn=crew,dc=example,dc=com'),
        );
        self::assertSame(
            [],
            $this->members('cn=staff,dc=example,dc=com'),
        );
    }

    public function test_an_entry_holding_more_values_than_the_cap_is_linked_in_a_batch_of_its_own(): void
    {
        $this->person('alice');
        $this->person('bob');
        $this->person('carol');
        $this->person('dave');
        $this->hold(
            'team',
            self::UUID_TEAM,
            'cn=alice,dc=example,dc=com',
            'cn=bob,dc=example,dc=com',
            'cn=carol,dc=example,dc=com',
            'cn=dave,dc=example,dc=com',
        );
        $this->hold(
            'crew',
            self::UUID_CREW,
            'cn=alice,dc=example,dc=com',
        );

        $this->subject->linkDeferred();

        self::assertSame(
            [
                'cn=alice,dc=example,dc=com',
                'cn=bob,dc=example,dc=com',
                'cn=carol,dc=example,dc=com',
                'cn=dave,dc=example,dc=com',
            ],
            $this->members('cn=team,dc=example,dc=com'),
        );
        self::assertSame(
            [],
            $this->members('cn=crew,dc=example,dc=com'),
        );
    }

    public function test_linking_reports_none_left_once_every_held_value_is_linked(): void
    {
        $this->person('alice');
        $this->hold(
            'team',
            self::UUID_TEAM,
            'cn=alice,dc=example,dc=com',
        );

        self::assertTrue($this->subject->linkDeferred());
        self::assertFalse($this->subject->linkDeferred());
    }

    private function person(string $name): void
    {
        $this->writer->store(new Entry(
            "cn={$name},dc=example,dc=com",
            new Attribute('cn', $name),
            new Attribute('entryUUID', Uuid::v4()),
        ));
    }

    private function hold(
        string $name,
        string $uuid,
        string ...$members,
    ): void {
        $this->subject->deferLinks(
            $uuid,
            new Entry(
                "cn={$name},dc=example,dc=com",
                new Attribute('cn', $name),
                new Attribute('member', ...$members),
                new Attribute('entryUUID', $uuid),
            ),
            function (Entry $entry, LinkDelta $links): void {
                $this->writer->store(
                    $entry,
                    links: $links,
                );
            },
        );
    }

    /**
     * @return list<string>
     */
    private function members(string $dn): array
    {
        $entry = $this->reader->find((new Dn($dn))->normalize());
        self::assertNotNull($entry);

        return array_values($entry->get('member')?->getValues() ?? []);
    }
}
