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

namespace Tests\Support\FreeDSx\Ldap\Storage;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ListEntryInterface;

use function array_map;
use function range;

/**
 * @mixin \PHPUnit\Framework\TestCase
 */
trait EntriesAtStorageContractTests
{
    public function test_entries_at_are_read_in_the_order_the_dns_are_given(): void
    {
        self::assertSame(
            [
                'cn=Bob,dc=foo,dc=bar',
                'cn=Alice,dc=foo,dc=bar',
            ],
            $this->storedDnsAt(
                $this->entriesAtContainer(),
                [
                    'cn=bob,dc=foo,dc=bar',
                    'cn=alice,dc=foo,dc=bar',
                ],
            ),
        );
    }

    public function test_entries_at_leave_out_a_dn_with_nothing_stored(): void
    {
        self::assertSame(
            ['cn=Alice,dc=foo,dc=bar'],
            $this->storedDnsAt(
                $this->entriesAtContainer(),
                [
                    'cn=gone,dc=foo,dc=bar',
                    'cn=alice,dc=foo,dc=bar',
                ],
            ),
        );
    }

    public function test_entries_at_carry_their_stored_attributes(): void
    {
        $entries = $this->entriesAtContainer()
            ->get(ListEntryInterface::class)
            ->entriesAt([(new Dn('cn=alice,dc=foo,dc=bar'))->normalize()]);

        self::assertSame(
            ['Alice'],
            $entries[0]->get('sn')?->getValues(),
        );
    }

    public function test_entries_at_are_read_beyond_the_first_batch(): void
    {
        $entries = array_map(
            static fn(int $i): Entry => new Entry(new Dn("cn=e$i,dc=foo,dc=bar")),
            range(
                0,
                500,
            ),
        );

        self::assertCount(
            501,
            $this->makeStorageContainer(...[
                new Entry(new Dn('dc=foo,dc=bar')),
                ...$entries,
            ])
                ->get(ListEntryInterface::class)
                ->entriesAt(array_map(
                    static fn(Entry $entry): Dn => $entry->getDn()->normalize(),
                    $entries,
                )),
        );
    }

    /**
     * @param Entry ...$entries Seeded, each given an entryUUID, before the contract runs.
     * @return Container the graph holding the seeded entries, which every storage contract resolves from
     */
    abstract protected function makeStorageContainer(Entry ...$entries): Container;

    private function entriesAtContainer(): Container
    {
        return $this->makeStorageContainer(
            new Entry(new Dn('dc=foo,dc=bar')),
            new Entry(
                new Dn('cn=Alice,dc=foo,dc=bar'),
                new Attribute('sn', 'Alice'),
            ),
            new Entry(
                new Dn('cn=Bob,dc=foo,dc=bar'),
                new Attribute('sn', 'Bob'),
            ),
        );
    }

    /**
     * @param list<string> $dns
     *
     * @return list<string> the stored DNs, as they were stored
     */
    private function storedDnsAt(
        Container $container,
        array $dns,
    ): array {
        return array_map(
            static fn(Entry $entry): string => $entry->getDn()->toString(),
            $container->get(ListEntryInterface::class)->entriesAt(array_map(
                static fn(string $dn): Dn => (new Dn($dn))->normalize(),
                $dns,
            )),
        );
    }
}
