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
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ListEntryInterface;

use function array_map;
use function range;
use function sort;

/**
 * @mixin \PHPUnit\Framework\TestCase
 */
trait ChildDnsStorageContractTests
{
    public function test_child_dns_are_the_canonical_dns_directly_beneath_each_parent(): void
    {
        self::assertSame(
            [
                'cn=alice,ou=people,dc=foo,dc=bar',
                'cn=bob,ou=people,dc=foo,dc=bar',
                'cn=carol,ou=groups,dc=foo,dc=bar',
            ],
            $this->childDnsOf(
                $this->childDnsContainer(),
                [
                    'ou=people,dc=foo,dc=bar',
                    'ou=groups,dc=foo,dc=bar',
                ],
            ),
        );
    }

    public function test_a_leaf_has_no_child_dns(): void
    {
        self::assertSame(
            [],
            $this->childDnsOf(
                $this->childDnsContainer(),
                ['cn=bob,ou=people,dc=foo,dc=bar'],
            ),
        );
    }

    public function test_child_dns_are_found_for_parents_beyond_the_first_batch(): void
    {
        $parents = array_map(
            static fn(int $i): Entry => new Entry(new Dn("ou=p$i,dc=foo,dc=bar")),
            range(
                0,
                500,
            ),
        );
        $container = $this->makeStorageContainer(...[
            new Entry(new Dn('dc=foo,dc=bar')),
            ...$parents,
            new Entry(new Dn('cn=Last,ou=p500,dc=foo,dc=bar')),
        ]);

        self::assertSame(
            ['cn=last,ou=p500,dc=foo,dc=bar'],
            $this->childDnsOf(
                $container,
                array_map(
                    static fn(Entry $parent): string => $parent->getDn()->normalizedString(),
                    $parents,
                ),
            ),
        );
    }

    public function test_an_entry_stored_under_a_missing_parent_is_still_a_child_of_that_dn(): void
    {
        $container = $this->makeStorageContainer(
            new Entry(new Dn('dc=foo,dc=bar')),
            new Entry(new Dn('cn=Orphan,ou=Missing,dc=foo,dc=bar')),
        );

        self::assertSame(
            ['cn=orphan,ou=missing,dc=foo,dc=bar'],
            $this->childDnsOf(
                $container,
                ['ou=missing,dc=foo,dc=bar'],
            ),
        );
    }

    /**
     * @param Entry ...$entries Seeded, each given an entryUUID, before the contract runs.
     * @return Container the graph holding the seeded entries, which every storage contract resolves from
     */
    abstract protected function makeStorageContainer(Entry ...$entries): Container;

    private function childDnsContainer(): Container
    {
        return $this->makeStorageContainer(
            new Entry(new Dn('dc=foo,dc=bar')),
            new Entry(new Dn('ou=People,dc=foo,dc=bar')),
            new Entry(new Dn('ou=Groups,dc=foo,dc=bar')),
            new Entry(new Dn('cn=Alice,ou=People,dc=foo,dc=bar')),
            new Entry(new Dn('cn=Bob,ou=People,dc=foo,dc=bar')),
            new Entry(new Dn('cn=Laptop,cn=Alice,ou=People,dc=foo,dc=bar')),
            new Entry(new Dn('cn=Carol,ou=Groups,dc=foo,dc=bar')),
        );
    }

    /**
     * @param list<string> $parents canonical DNs
     *
     * @return list<string> sorted, since no order is promised
     */
    private function childDnsOf(
        Container $container,
        array $parents,
    ): array {
        $dns = $container->get(ListEntryInterface::class)->childDns($parents);
        sort($dns);

        return $dns;
    }
}
