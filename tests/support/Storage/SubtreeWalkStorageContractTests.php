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
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Server\Backend\Storage\Directory\SubtreeEnumerator;

use function array_filter;
use function array_map;
use function array_search;
use function count;
use function iterator_to_array;
use function range;
use function sort;

/**
 * @mixin \PHPUnit\Framework\TestCase
 */
trait SubtreeWalkStorageContractTests
{
    public function test_the_walk_yields_every_entry_after_its_children_and_the_base_last(): void
    {
        $walked = $this->walk(
            $this->walkContainer(),
            'ou=people,dc=foo,dc=bar',
        );

        self::assertSame(
            'ou=people,dc=foo,dc=bar',
            $walked[count($walked) - 1],
        );
        self::assertLessThan(
            $this->positionOf(
                $walked,
                'cn=alice,ou=people,dc=foo,dc=bar',
            ),
            $this->positionOf(
                $walked,
                'cn=laptop,cn=alice,ou=people,dc=foo,dc=bar',
            ),
        );
    }

    public function test_the_walk_yields_each_entry_beneath_the_base_once(): void
    {
        $walked = $this->walk(
            $this->walkContainer(),
            'ou=people,dc=foo,dc=bar',
        );
        sort($walked);

        self::assertSame(
            [
                'cn=alice,ou=people,dc=foo,dc=bar',
                'cn=bob,ou=people,dc=foo,dc=bar',
                'cn=laptop,cn=alice,ou=people,dc=foo,dc=bar',
                'cn=link,ou=people,dc=foo,dc=bar',
                'cn=policy,ou=people,dc=foo,dc=bar',
                'ou=people,dc=foo,dc=bar',
            ],
            $walked,
        );
    }

    public function test_the_walk_of_a_leaf_is_the_leaf_alone(): void
    {
        self::assertSame(
            ['cn=bob,ou=people,dc=foo,dc=bar'],
            $this->walk(
                $this->walkContainer(),
                'cn=bob,ou=people,dc=foo,dc=bar',
            ),
        );
    }

    public function test_the_walk_reads_a_container_with_more_children_than_one_page(): void
    {
        $children = array_map(
            static fn(int $i): Entry => new Entry(new Dn("cn=c$i,ou=wide,dc=foo,dc=bar")),
            range(
                0,
                500,
            ),
        );
        $container = $this->makeStorageContainer(...[
            new Entry(new Dn('dc=foo,dc=bar')),
            new Entry(new Dn('ou=Wide,dc=foo,dc=bar')),
            ...$children,
            new Entry(new Dn('cn=Below,cn=c500,ou=wide,dc=foo,dc=bar')),
        ]);
        $walked = $this->walk(
            $container,
            'ou=wide,dc=foo,dc=bar',
        );

        self::assertCount(
            503,
            $walked,
        );
        self::assertLessThan(
            $this->positionOf(
                $walked,
                'cn=c500,ou=wide,dc=foo,dc=bar',
            ),
            $this->positionOf(
                $walked,
                'cn=below,cn=c500,ou=wide,dc=foo,dc=bar',
            ),
        );
    }

    public function test_the_walk_does_not_reach_an_entry_stored_under_a_missing_parent(): void
    {
        $container = $this->makeStorageContainer(
            new Entry(new Dn('dc=foo,dc=bar')),
            new Entry(new Dn('cn=Orphan,ou=Missing,dc=foo,dc=bar')),
        );

        self::assertSame(
            ['dc=foo,dc=bar'],
            $this->walk(
                $container,
                'dc=foo,dc=bar',
            ),
        );
    }

    public function test_the_parents_first_walk_yields_the_base_first_and_each_entry_after_its_parent(): void
    {
        $walked = $this->dnsOf($this->walkParentsFirst(
            $this->walkContainer(),
            'ou=people,dc=foo,dc=bar',
        ));

        self::assertSame(
            'ou=people,dc=foo,dc=bar',
            $walked[0],
        );
        self::assertLessThan(
            $this->positionOf(
                $walked,
                'cn=laptop,cn=alice,ou=people,dc=foo,dc=bar',
            ),
            $this->positionOf(
                $walked,
                'cn=alice,ou=people,dc=foo,dc=bar',
            ),
        );
    }

    public function test_the_parents_first_walk_yields_each_entry_beneath_the_base_once(): void
    {
        $walked = $this->dnsOf($this->walkParentsFirst(
            $this->walkContainer(),
            'ou=people,dc=foo,dc=bar',
        ));
        sort($walked);

        self::assertSame(
            [
                'cn=alice,ou=people,dc=foo,dc=bar',
                'cn=bob,ou=people,dc=foo,dc=bar',
                'cn=laptop,cn=alice,ou=people,dc=foo,dc=bar',
                'cn=link,ou=people,dc=foo,dc=bar',
                'cn=policy,ou=people,dc=foo,dc=bar',
                'ou=people,dc=foo,dc=bar',
            ],
            $walked,
        );
    }

    public function test_the_parents_first_walk_finishes_a_container_after_descending_into_its_first_child(): void
    {
        $children = array_map(
            static fn(int $i): Entry => new Entry(new Dn("cn=c$i,ou=wide,dc=foo,dc=bar")),
            range(
                0,
                1000,
            ),
        );
        $container = $this->makeStorageContainer(...[
            new Entry(new Dn('dc=foo,dc=bar')),
            new Entry(new Dn('ou=Wide,dc=foo,dc=bar')),
            ...$children,
            new Entry(new Dn('cn=Below,cn=c0,ou=wide,dc=foo,dc=bar')),
        ]);
        $walked = $this->dnsOf($this->walkParentsFirst(
            $container,
            'ou=wide,dc=foo,dc=bar',
        ));

        self::assertCount(
            1003,
            $walked,
        );
        self::assertLessThan(
            $this->positionOf(
                $walked,
                'cn=below,cn=c0,ou=wide,dc=foo,dc=bar',
            ),
            $this->positionOf(
                $walked,
                'cn=c0,ou=wide,dc=foo,dc=bar',
            ),
        );
    }

    public function test_the_parents_first_walk_does_not_reach_an_entry_stored_under_a_missing_parent(): void
    {
        $container = $this->makeStorageContainer(
            new Entry(new Dn('dc=foo,dc=bar')),
            new Entry(new Dn('cn=Orphan,ou=Missing,dc=foo,dc=bar')),
        );

        self::assertSame(
            ['dc=foo,dc=bar'],
            $this->dnsOf($this->walkParentsFirst(
                $container,
                'dc=foo,dc=bar',
            )),
        );
    }

    public function test_the_parents_first_walk_of_a_missing_base_yields_nothing(): void
    {
        self::assertSame(
            [],
            $this->walkParentsFirst(
                $this->walkContainer(),
                'ou=missing,dc=foo,dc=bar',
            ),
        );
    }

    public function test_no_entry_the_parents_first_walk_yields_carries_the_child_flag(): void
    {
        $flagged = array_filter(
            $this->walkParentsFirst(
                $this->walkContainer(),
                'dc=foo,dc=bar',
            ),
            static fn(Entry $entry): bool => $entry->has(AttributeTypeOid::NAME_HAS_SUBORDINATES),
        );

        self::assertSame(
            [],
            $flagged,
        );
    }

    public function test_children_outside_are_the_children_not_among_the_entries_given(): void
    {
        $subtree = $this->walkContainer()->get(SubtreeEnumerator::class);

        self::assertSame(
            ['cn=laptop,cn=alice,ou=people,dc=foo,dc=bar'],
            $subtree->childrenOutside([
                'cn=alice,ou=people,dc=foo,dc=bar',
                'cn=bob,ou=people,dc=foo,dc=bar',
            ]),
        );
    }

    public function test_children_outside_are_none_when_every_child_is_among_the_entries_given(): void
    {
        $subtree = $this->walkContainer()->get(SubtreeEnumerator::class);

        self::assertSame(
            [],
            $subtree->childrenOutside([
                'cn=laptop,cn=alice,ou=people,dc=foo,dc=bar',
                'cn=alice,ou=people,dc=foo,dc=bar',
            ]),
        );
    }

    /**
     * @param Entry ...$entries Seeded, each given an entryUUID, before the contract runs.
     * @return Container the graph holding the seeded entries, which every storage contract resolves from
     */
    abstract protected function makeStorageContainer(Entry ...$entries): Container;

    private function walkContainer(): Container
    {
        return $this->makeStorageContainer(
            new Entry(new Dn('dc=foo,dc=bar')),
            new Entry(new Dn('ou=People,dc=foo,dc=bar')),
            new Entry(new Dn('cn=Alice,ou=People,dc=foo,dc=bar')),
            new Entry(new Dn('cn=Bob,ou=People,dc=foo,dc=bar')),
            new Entry(new Dn('cn=Laptop,cn=Alice,ou=People,dc=foo,dc=bar')),
            new Entry(
                new Dn('cn=Policy,ou=People,dc=foo,dc=bar'),
                new Attribute(
                    'objectClass',
                    'top',
                    'subentry',
                ),
            ),
            new Entry(
                new Dn('cn=Link,ou=People,dc=foo,dc=bar'),
                new Attribute(
                    'objectClass',
                    'top',
                    'alias',
                ),
                new Attribute(
                    'aliasedObjectName',
                    'ou=Groups,dc=foo,dc=bar',
                ),
            ),
        );
    }

    /**
     * @return list<string>
     */
    private function walk(
        Container $container,
        string $base,
    ): array {
        return iterator_to_array(
            $container->get(SubtreeEnumerator::class)->leavesFirst(new Dn($base)),
            false,
        );
    }

    /**
     * @return list<Entry>
     */
    private function walkParentsFirst(
        Container $container,
        string $base,
    ): array {
        return iterator_to_array(
            $container->get(SubtreeEnumerator::class)->parentsFirst(new Dn($base)),
            false,
        );
    }

    /**
     * @param list<Entry> $entries
     *
     * @return list<string>
     */
    private function dnsOf(array $entries): array
    {
        return array_map(
            static fn(Entry $entry): string => $entry->getDn()->normalizedString(),
            $entries,
        );
    }

    /**
     * @param list<string> $walked
     */
    private function positionOf(
        array $walked,
        string $dn,
    ): int {
        $position = array_search(
            $dn,
            $walked,
            true,
        );
        self::assertIsInt($position);

        return $position;
    }
}
