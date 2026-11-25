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
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Option;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\DeferredLinksInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\LinkedValueLookupInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ListEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Import\LdapImporter;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkDelta;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkTarget;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkWindow;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use FreeDSx\Ldap\Server\Backend\StorageReadBackend;
use FreeDSx\Ldap\Server\Backend\Write\Operation\Linked\LinkedChangeReplay;
use FreeDSx\Ldap\Server\Config\Storage\StorageConfigInterface;
use FreeDSx\Ldap\Server\Subentry\SubentryVisibility;

use function array_map;
use function array_values;
use function iterator_to_array;
use function str_repeat;
use function strtolower;

/**
 * How a store keeps the optional uid a Name and Optional UID value carries after the name it links.
 *
 * @mixin \PHPUnit\Framework\TestCase
 */
trait LinkedUidStorageContractTests
{
    public function test_a_link_keeps_the_uid_it_was_written_with(): void
    {
        $container = $this->uidLinkContainer();

        $this->uidLinkGroup(
            $container,
            'team',
            "cn=Bob,dc=example,dc=com#'0101'B",
            'cn=Bob,dc=example,dc=com',
            "cn=Alice,dc=example,dc=com#''B",
        );

        self::assertEqualsCanonicalizing(
            ["cn=Bob,dc=example,dc=com#'0101'B", 'cn=Bob,dc=example,dc=com', "cn=Alice,dc=example,dc=com#''B"],
            $this->uidLinksOf(
                $container,
                'team',
            ),
        );
    }

    public function test_a_link_naming_an_entry_stored_later_in_the_batch_keeps_its_uid(): void
    {
        $container = $this->uidLinkContainer();

        $container->get(LdapImporter::class)->importEntries([
            Entry::fromArray(
                'cn=crew,dc=example,dc=com',
                ['cn' => ['crew'], UidLinkSchema::ATTRIBUTE => ["cn=Carol,dc=example,dc=com#'01'B"]],
            ),
            Entry::fromArray(
                'cn=Carol,dc=example,dc=com',
                ['cn' => ['Carol']],
            ),
        ]);

        self::assertSame(
            ["cn=Carol,dc=example,dc=com#'01'B"],
            $this->uidLinksOf(
                $container,
                'crew',
            ),
        );
    }

    public function test_a_held_back_link_keeps_its_uid(): void
    {
        $container = $this->uidLinkContainer();
        $writer = $container->get(WriteEntryInterface::class);
        $deferred = $container->get(DeferredLinksInterface::class);

        $deferred->deferLinks(
            'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
            Entry::fromArray(
                'cn=crew,dc=example,dc=com',
                [
                    'cn' => ['crew'],
                    UidLinkSchema::ATTRIBUTE => ["cn=Bob,dc=example,dc=com#'01'B"],
                    'entryUUID' => ['cccccccc-cccc-4ccc-8ccc-cccccccccccc'],
                ],
            ),
            static function (
                Entry $entry,
                LinkDelta $links,
            ) use ($writer): void {
                $writer->store(
                    $entry,
                    links: $links,
                );
            },
        );
        $deferred->linkDeferred();

        self::assertSame(
            ["cn=Bob,dc=example,dc=com#'01'B"],
            $this->uidLinksOf(
                $container,
                'crew',
            ),
        );
    }

    public function test_a_link_is_held_only_with_the_uid_it_was_written_with(): void
    {
        $container = $this->uidLinkContainer();
        $this->uidLinkGroup(
            $container,
            'team',
            "cn=Bob,dc=example,dc=com#'0101'B",
            "cn=Alice,dc=example,dc=com#''B",
        );

        self::assertEqualsCanonicalizing(
            ["CN=Bob, DC=example, DC=com#'0101'b", "cn=Alice,dc=example,dc=com#''B"],
            $container->get(LinkedValueLookupInterface::class)->heldLinkValues(
                new Dn('cn=team,dc=example,dc=com'),
                UidLinkSchema::ATTRIBUTE,
                [
                    "CN=Bob, DC=example, DC=com#'0101'b",
                    'cn=Bob,dc=example,dc=com',
                    "cn=Alice,dc=example,dc=com#''B",
                    'cn=Alice,dc=example,dc=com',
                ],
            ),
        );
    }

    public function test_a_change_naming_a_target_without_the_uid_it_is_held_with_is_refused(): void
    {
        $container = $this->uidLinkContainer();
        $this->uidLinkGroup(
            $container,
            'team',
            "cn=Bob,dc=example,dc=com#'0101'B",
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::NO_SUCH_ATTRIBUTE);

        $container->get(LinkedChangeReplay::class)->settle(
            [Change::delete(
                UidLinkSchema::ATTRIBUTE,
                'cn=Bob,dc=example,dc=com',
            )],
            new Dn('cn=team,dc=example,dc=com'),
        );
    }

    public function test_a_delta_removes_only_the_uid_it_names(): void
    {
        $container = $this->uidLinkContainer();
        $this->uidLinkGroup(
            $container,
            'team',
            "cn=Bob,dc=example,dc=com#'01'B",
            "cn=Bob,dc=example,dc=com#'10'B",
        );

        $container->get(WriteEntryInterface::class)->store(
            EntryFixture::withUuid(Entry::fromArray(
                'cn=team,dc=example,dc=com',
                ['cn' => ['team']],
            )),
            links: new LinkDelta(removed: [UidLinkSchema::ATTRIBUTE => ["CN=Bob, DC=example, DC=com#'01'b"]]),
        );

        self::assertSame(
            ["cn=Bob,dc=example,dc=com#'10'B"],
            $this->uidLinksOf(
                $container,
                'team',
            ),
        );
    }

    public function test_an_equality_filter_matches_the_uid_as_well_as_the_name(): void
    {
        $container = $this->uidLinkContainer();
        $this->uidLinkGroup(
            $container,
            'team',
            "cn=Bob,dc=example,dc=com#'0101'B",
        );

        self::assertSame(
            [['team'], []],
            [
                $this->uidLinkMatches(
                    $container,
                    Filters::equal(
                        UidLinkSchema::ATTRIBUTE,
                        "cn=Bob,dc=example,dc=com#'0101'B",
                    ),
                ),
                $this->uidLinkMatches(
                    $container,
                    Filters::equal(
                        UidLinkSchema::ATTRIBUTE,
                        'cn=Bob,dc=example,dc=com',
                    ),
                ),
            ],
        );
    }

    public function test_a_sort_orders_links_by_the_name_then_the_uid(): void
    {
        $container = $this->uidLinkContainer();

        foreach (['u2' => "#''B", 'u1' => '', 'u3' => "#'0'B"] as $name => $uid) {
            $this->uidLinkGroup(
                $container,
                $name,
                'cn=Bob,dc=example,dc=com' . $uid,
            );
        }

        self::assertSame(
            [['u1', 'u2', 'u3'], ['u3', 'u2', 'u1']],
            [
                $this->uidLinkMatches(
                    $container,
                    Filters::present(UidLinkSchema::ATTRIBUTE),
                    SortKey::ascending(
                        UidLinkSchema::ATTRIBUTE,
                        'uniqueMemberMatch',
                    ),
                ),
                $this->uidLinkMatches(
                    $container,
                    Filters::present(UidLinkSchema::ATTRIBUTE),
                    SortKey::descending(
                        UidLinkSchema::ATTRIBUTE,
                        'uniqueMemberMatch',
                    ),
                ),
            ],
        );
    }

    public function test_slices_of_a_target_held_with_several_uids_give_each_value_once(): void
    {
        $container = $this->uidLinkContainer();
        $values = [
            'cn=Alice,dc=example,dc=com',
            'cn=Bob,dc=example,dc=com',
            "cn=Bob,dc=example,dc=com#''B",
            "cn=Bob,dc=example,dc=com#'01'B",
            "cn=Bob,dc=example,dc=com#'10'B",
        ];
        $this->uidLinkGroup(
            $container,
            'team',
            ...$values,
        );
        $sliced = [];

        foreach (['0-1', '2-3', '4-*'] as $range) {
            $sliced = [
                ...$sliced,
                ...$this->uidLinkSlice(
                    $container,
                    'team',
                    $range,
                ),
            ];
        }

        self::assertEqualsCanonicalizing(
            $values,
            $sliced,
        );
    }

    public function test_a_uid_at_the_longest_length_kept_is_stored(): void
    {
        $container = $this->uidLinkContainer();
        $value = 'cn=Bob,dc=example,dc=com' . self::uidOfBits(LinkTarget::MAX_UID_BITS);

        $this->uidLinkGroup(
            $container,
            'team',
            $value,
        );

        self::assertSame(
            [$value],
            $this->uidLinksOf(
                $container,
                'team',
            ),
        );
    }

    public function test_a_uid_longer_than_a_store_keeps_is_refused(): void
    {
        $container = $this->uidLinkContainer();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $this->uidLinkGroup(
            $container,
            'team',
            'cn=Bob,dc=example,dc=com' . self::uidOfBits(LinkTarget::MAX_UID_BITS + 1),
        );
    }

    public function test_a_delta_adding_a_uid_longer_than_a_store_keeps_is_refused(): void
    {
        $container = $this->uidLinkContainer();
        $this->uidLinkGroup(
            $container,
            'team',
            'cn=Alice,dc=example,dc=com',
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $container->get(WriteEntryInterface::class)->store(
            EntryFixture::withUuid(Entry::fromArray(
                'cn=team,dc=example,dc=com',
                ['cn' => ['team']],
            )),
            links: new LinkDelta(added: [
                UidLinkSchema::ATTRIBUTE => ['cn=Bob,dc=example,dc=com' . self::uidOfBits(LinkTarget::MAX_UID_BITS + 1)],
            ]),
        );
    }

    public function test_a_write_refused_for_a_uid_too_long_leaves_the_entry_it_would_replace(): void
    {
        $container = $this->uidLinkContainer();
        $this->uidLinkGroup(
            $container,
            'team',
            'cn=Alice,dc=example,dc=com',
        );
        $refused = null;

        try {
            $container->get(WriteEntryInterface::class)->store(Entry::fromArray(
                'cn=team,dc=example,dc=com',
                [
                    'cn' => ['team'],
                    UidLinkSchema::ATTRIBUTE => ['cn=Bob,dc=example,dc=com' . self::uidOfBits(LinkTarget::MAX_UID_BITS + 1)],
                    'entryUUID' => ['dddddddd-dddd-4ddd-8ddd-dddddddddddd'],
                ],
            ));
        } catch (OperationException $e) {
            $refused = $e->getCode();
        }

        self::assertSame(
            ResultCode::ADMIN_LIMIT_EXCEEDED,
            $refused,
        );
        self::assertSame(
            ['cn=Alice,dc=example,dc=com'],
            $this->uidLinksOf(
                $container,
                'team',
            ),
        );
    }

    public function test_a_new_entry_refused_for_a_uid_too_long_is_not_left_below_its_parent(): void
    {
        $container = $this->uidLinkContainer();
        $refused = null;

        try {
            $this->uidLinkGroup(
                $container,
                'team',
                'cn=Bob,dc=example,dc=com' . self::uidOfBits(LinkTarget::MAX_UID_BITS + 1),
            );
        } catch (OperationException $e) {
            $refused = $e->getCode();
        }

        self::assertSame(
            ResultCode::ADMIN_LIMIT_EXCEEDED,
            $refused,
        );
        self::assertEqualsCanonicalizing(
            ['cn=alice,dc=example,dc=com', 'cn=bob,dc=example,dc=com'],
            $container->get(ListEntryInterface::class)->childDns(['dc=example,dc=com']),
        );
    }

    /**
     * The store a host tests, whose schema adds a linked attribute carrying a uid.
     */
    abstract protected function uidLinkStorage(): StorageConfigInterface;

    /**
     * A container over the host's store holding the base entry, Alice and Bob.
     */
    private function uidLinkContainer(): Container
    {
        $container = Container::forServer(UidLinkSchema::options($this->uidLinkStorage()));
        $writer = $container->get(WriteEntryInterface::class);

        foreach (['dc=example,dc=com' => 'dc', 'cn=Alice,dc=example,dc=com' => 'cn', 'cn=Bob,dc=example,dc=com' => 'cn'] as $dn => $rdn) {
            $writer->store(EntryFixture::withUuid(Entry::fromArray(
                $dn,
                [$rdn => [(new Dn($dn))->getRdn()->getValue()]],
            )));
        }

        return $container;
    }

    private function uidLinkGroup(
        Container $container,
        string $name,
        string ...$values,
    ): void {
        $container->get(WriteEntryInterface::class)->store(EntryFixture::withUuid(Entry::fromArray(
            "cn=$name,dc=example,dc=com",
            ['cn' => [$name], UidLinkSchema::ATTRIBUTE => $values],
        )));
    }

    /**
     * @return list<string>
     */
    private function uidLinksOf(
        Container $container,
        string $name,
    ): array {
        $entry = $container->get(ReadEntryInterface::class)->find((new Dn("cn=$name,dc=example,dc=com"))->normalize());
        self::assertNotNull($entry);

        return array_values($entry->get(UidLinkSchema::ATTRIBUTE)?->getValues() ?? []);
    }

    /**
     * The values one slice of a group's links reads.
     *
     * @return list<string>
     */
    private function uidLinkSlice(
        Container $container,
        string $name,
        string $range,
    ): array {
        $window = LinkWindow::fromOption(new Option("range=$range"));
        self::assertNotNull($window);
        $entry = $container->get(ReadEntryInterface::class)->find(
            (new Dn("cn=$name,dc=example,dc=com"))->normalize(),
            new EntryProjection(windows: [strtolower(UidLinkSchema::ATTRIBUTE) => $window]),
        );
        self::assertNotNull($entry);

        return array_values($entry->get(UidLinkSchema::ATTRIBUTE)?->getValues() ?? []);
    }

    /**
     * The cn of each entry the filter matches, in the order the sort key put them.
     *
     * @return list<string>
     */
    private function uidLinkMatches(
        Container $container,
        FilterInterface $filter,
        ?SortKey $sortKey = null,
    ): array {
        $controls = $sortKey === null
            ? new ControlBag()
            : new ControlBag(new SortingControl($sortKey));
        $request = (new SearchRequest(
            $filter,
            'cn',
        ))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();
        $entries = $container->get(StorageReadBackend::class)->search(
            $request,
            SubentryVisibility::All,
            $controls,
        )->entries();

        return array_values(array_map(
            static fn(Entry $entry): string => (string) $entry->get('cn')?->firstValue(),
            iterator_to_array(
                $entries,
                false,
            ),
        ));
    }

    private static function uidOfBits(int $bits): string
    {
        return "#'" . str_repeat(
            '1',
            $bits,
        ) . "'B";
    }
}
