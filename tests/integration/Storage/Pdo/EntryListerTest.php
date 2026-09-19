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
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnectionProviderInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\SharedPdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoSchema;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query\EntryLister;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\Config\Storage\SubstringIndexMode;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Pdo\EntryLinkFixtureTrait;
use Tests\Support\FreeDSx\Ldap\Pdo\RecordingPdo;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class EntryListerTest extends TestCase
{
    use EntryLinkFixtureTrait;

    private const BASE = 'dc=example,dc=com';

    private RecordingPdo $pdo;

    private EntryLister $subject;

    private PdoStorage $storage;

    protected function setUp(): void
    {
        $this->pdo = new RecordingPdo('sqlite::memory:');
        (new PdoSchema(new SqliteDialect()))->apply($this->pdo);

        $container = Container::forServer(
            TestServerOptions::sqlite(),
            [PdoConnectionProviderInterface::class => new SharedPdoConnectionProvider($this->pdo)],
        );
        $this->subject = $container->get(EntryLister::class);
        $this->storage = $container->get(PdoStorage::class);

        $this->storage->store(new Entry(
            new Dn(self::BASE),
            new Attribute('dc', 'example'),
        ));
    }

    /**
     * Canonicalizing drops the space in "cn=spaced, dc=..." where LOWER() keeps it, so keying the sort off the
     * lowercased DN rather than lc_dn misses this entry's sidecar rows and sorts it as if the attribute were unset.
     */
    public function test_sorting_keys_off_a_dn_whose_canonical_form_differs_from_its_literal_case(): void
    {
        $this->store(
            'cn=spaced, dc=example,dc=com',
            new Attribute('sn', 'aaa'),
        );
        $this->store(
            'cn=plain,dc=example,dc=com',
            new Attribute('sn', 'bbb'),
        );

        self::assertSame(
            ['cn=spaced, dc=example,dc=com', 'cn=plain,dc=example,dc=com'],
            $this->dns(new StorageListOptions(
                baseDn: new Dn(self::BASE),
                subtree: true,
                filter: Filters::present('sn'),
                sortKeys: [new SortKey('sn')],
            )),
        );
    }

    public function test_lists_differing_only_in_size_limit_share_one_prepared_statement(): void
    {
        foreach (range(1, 3) as $i) {
            $this->store(
                "cn=e{$i},dc=example,dc=com",
                new Attribute('sn', 'x'),
            );
        }

        foreach ([1, 2, 3] as $maxEntries) {
            $this->dns(new StorageListOptions(
                baseDn: new Dn(self::BASE),
                subtree: true,
                filter: Filters::equal('sn', 'x'),
                maxEntries: $maxEntries,
            ));
        }

        self::assertCount(
            1,
            array_filter(
                $this->pdo->preparedMatching('LIMIT ?'),
                static fn(string $query): bool => !str_contains($query, 'entry_attribute_links'),
            ),
        );
    }

    public function test_a_projection_that_materializes_nothing_still_yields_the_dns(): void
    {
        $this->store(
            'cn=bob,dc=example,dc=com',
            new Attribute('sn', 'x'),
        );

        $entries = iterator_to_array($this->subject->list(new StorageListOptions(
            baseDn: new Dn(self::BASE),
            subtree: true,
            filter: Filters::equal('sn', 'x'),
            projection: new EntryProjection([]),
        ))->entries());

        self::assertCount(
            1,
            $entries,
        );
        self::assertSame(
            'cn=bob,dc=example,dc=com',
            $entries[0]->getDn()->toString(),
        );
        self::assertSame(
            [],
            $entries[0]->toArray(),
        );
    }

    public function test_listing_from_the_root_returns_every_entry(): void
    {
        $this->store('cn=Alice,dc=example,dc=com');

        self::assertCount(
            2,
            $this->dns(StorageListOptions::matchAll(
                new Dn(''),
                true,
            )),
        );
    }

    public function test_interleaved_lists_do_not_share_cursor_state(): void
    {
        $this->store('cn=Alice,dc=example,dc=com');
        $this->store('cn=Bob,dc=example,dc=com');
        $this->store('cn=Carol,dc=example,dc=com');
        $options = StorageListOptions::matchAll(
            new Dn(self::BASE),
            true,
        );

        $outer = $this->subject->list($options)->entries();
        $outer->current();
        $outer->next();

        $inner = iterator_to_array($this->subject->list($options)->entries());

        $remaining = [];
        while ($outer->valid()) {
            $remaining[] = $outer->current();
            $outer->next();
        }

        self::assertCount(
            4,
            $inner,
        );
        // The outer list yielded one entry before the inner one ran, so the other three must still come through.
        self::assertCount(
            3,
            $remaining,
        );
    }

    /**
     * The trigram predicate only narrows, so excluding a true match cannot be undone by the caller's re-check.
     */
    public function test_a_substring_match_past_the_indexed_window_is_still_a_candidate(): void
    {
        [$subject, $storage] = $this->trigramIndexed();
        $storage->store(new Entry(
            new Dn('cn=late,dc=example,dc=com'),
            new Attribute('cn', 'late'),
            new Attribute('sn', str_repeat('x', 300) . 'needle'),
        ));

        self::assertSame(
            ['cn=late,dc=example,dc=com'],
            $this->dnsFrom(
                $subject,
                Filters::contains('sn', 'needle'),
            ),
        );
    }

    public function test_a_substring_inside_the_indexed_window_still_narrows(): void
    {
        [$subject, $storage] = $this->trigramIndexed();
        $storage->store(new Entry(
            new Dn('cn=hit,dc=example,dc=com'),
            new Attribute('cn', 'hit'),
            new Attribute('sn', 'haystack-needle'),
        ));
        $storage->store(new Entry(
            new Dn('cn=miss,dc=example,dc=com'),
            new Attribute('cn', 'miss'),
            new Attribute('sn', 'nothing-here'),
        ));

        self::assertSame(
            ['cn=hit,dc=example,dc=com'],
            $this->dnsFrom(
                $subject,
                Filters::contains('sn', 'needle'),
            ),
        );
    }

    public function test_a_listed_entry_carries_its_linked_values(): void
    {
        $this->store(
            'cn=Bob,dc=example,dc=com',
            new Attribute('cn', 'Bob'),
        );
        $this->store(
            'cn=Admins,dc=example,dc=com',
            new Attribute('cn', 'Admins'),
        );
        $this->linkTogether(
            $this->pdo,
            'cn=admins,dc=example,dc=com',
            'cn=bob,dc=example,dc=com',
        );

        $admins = null;
        foreach ($this->subject->list($this->allWithCn())->entries() as $entry) {
            if ($entry->getDn()->toString() === 'cn=Admins,dc=example,dc=com') {
                $admins = $entry;
            }
        }

        self::assertSame(
            ['cn=Bob,dc=example,dc=com'],
            $admins?->get('member')?->getValues(),
        );
    }

    public function test_a_listed_group_over_the_cap_is_bounded_while_a_smaller_one_stays_whole(): void
    {
        $this->groupOf('Big', 5);
        $this->groupOf('Small', 2);

        $members = $this->linkedValuesByDn(3);

        self::assertSame(
            ['member;range=0-2'],
            array_keys($members['cn=Big,dc=example,dc=com']),
        );
        self::assertCount(
            3,
            $members['cn=Big,dc=example,dc=com']['member;range=0-2'],
        );
        self::assertSame(
            ['member'],
            array_keys($members['cn=Small,dc=example,dc=com']),
        );
        self::assertCount(
            2,
            $members['cn=Small,dc=example,dc=com']['member'],
        );
    }

    public function test_links_totalling_more_than_the_cap_across_entries_are_each_returned_whole(): void
    {
        $this->groupOf('First', 2);
        $this->groupOf('Second', 2);

        $members = $this->linkedValuesByDn(3);

        self::assertCount(
            2,
            $members['cn=First,dc=example,dc=com']['member'] ?? [],
        );
        self::assertCount(
            2,
            $members['cn=Second,dc=example,dc=com']['member'] ?? [],
        );
    }

    public function test_a_list_materializing_nothing_asks_for_no_links(): void
    {
        $this->store(
            'cn=Admins,dc=example,dc=com',
            new Attribute('cn', 'Admins'),
        );
        $this->pdo->prepared = [];

        $this->dns($this->allWithCn(attributes: []));

        self::assertSame(
            [],
            $this->pdo->preparedMatching('entry_attribute_links'),
        );
    }

    public function test_a_projection_naming_no_linked_type_asks_for_no_links(): void
    {
        $this->store(
            'cn=Admins,dc=example,dc=com',
            new Attribute('cn', 'Admins'),
        );
        $this->pdo->prepared = [];

        $this->dns($this->allWithCn(attributes: ['cn']));

        self::assertSame(
            [],
            $this->pdo->preparedMatching('entry_attribute_links'),
        );
    }

    private function store(
        string $dn,
        Attribute ...$attributes,
    ): void {
        $this->storage->store(new Entry(
            new Dn($dn),
            ...$attributes,
        ));
    }

    private function groupOf(
        string $name,
        int $members,
    ): void {
        $this->store(
            sprintf('cn=%s,dc=example,dc=com', $name),
            new Attribute('cn', $name),
        );

        for ($i = 0; $i < $members; $i++) {
            $this->store(
                sprintf('cn=%s%d,dc=example,dc=com', $name, $i),
                new Attribute('cn', $name . $i),
            );
            $this->linkTogether(
                $this->pdo,
                strtolower(sprintf('cn=%s,dc=example,dc=com', $name)),
                strtolower(sprintf('cn=%s%d,dc=example,dc=com', $name, $i)),
            );
        }
    }

    /**
     * The linked attributes of every listed entry holding one, keyed by DN and then by returned name.
     *
     * @return array<string, array<string, list<string>>>
     */
    private function linkedValuesByDn(int $cap): array
    {
        $options = new StorageListOptions(
            baseDn: new Dn(self::BASE),
            subtree: true,
            filter: Filters::present('cn'),
            projection: new EntryProjection(linkCap: $cap),
        );
        $linked = [];

        foreach ($this->subject->list($options)->entries() as $entry) {
            foreach ($entry->getAttributes() as $attribute) {
                if ($attribute->getName() === 'member') {
                    $linked[$entry->getDn()->toString()][$attribute->getDescription()] = array_values($attribute->getValues());
                }
            }
        }

        return $linked;
    }

    /**
     * @param list<string>|null $attributes
     */
    private function allWithCn(?array $attributes = null): StorageListOptions
    {
        return new StorageListOptions(
            baseDn: new Dn(self::BASE),
            subtree: true,
            filter: Filters::present('cn'),
            projection: new EntryProjection($attributes),
        );
    }

    /**
     * @return list<string>
     */
    private function dns(StorageListOptions $options): array
    {
        $dns = [];
        foreach ($this->subject->list($options)->entries() as $entry) {
            $dns[] = $entry->getDn()->toString();
        }

        return $dns;
    }

    /**
     * @return list<string>
     */
    private function dnsFrom(
        EntryLister $lister,
        FilterInterface $filter,
    ): array {
        $dns = [];
        foreach ($lister->list(new StorageListOptions(new Dn(self::BASE), true, $filter))->entries() as $entry) {
            $dns[] = $entry->getDn()->toString();
        }

        return $dns;
    }

    /**
     * A lister and storage over a fresh database set up with the trigram substring index.
     *
     * @return array{EntryLister, PdoStorage}
     */
    private function trigramIndexed(): array
    {
        $container = Container::forServer(TestServerOptions::forStorage(
            PdoConfig::forSqlite(':memory:')
                ->setSubstringIndexMode(SubstringIndexMode::Trigram),
        ));
        $storage = $container->get(PdoStorage::class);
        $storage->store(new Entry(
            new Dn(self::BASE),
            new Attribute('dc', 'example'),
        ));

        return [
            $container->get(EntryLister::class),
            $storage,
        ];
    }
}
