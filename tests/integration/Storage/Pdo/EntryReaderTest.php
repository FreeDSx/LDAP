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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query\EntryReader;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Writer\EntryWriter;
use FreeDSx\Ldap\Entry\Option;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkWindow;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Pdo\EntryLinkFixtureTrait;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class EntryReaderTest extends TestCase
{
    use EntryLinkFixtureTrait;

    use ServerContainerTrait;

    private EntryReader $subject;

    private EntryWriter $storage;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(EntryReader::class);
        $this->storage = $this->fromContainer(EntryWriter::class);
    }

    public function test_find_returns_the_entry_under_its_stored_dn(): void
    {
        $this->store('cn=Alice,dc=example,dc=com');

        self::assertSame(
            'cn=Alice,dc=example,dc=com',
            $this->subject->find(new Dn('cn=alice,dc=example,dc=com'))?->getDn()->toString(),
        );
    }

    public function test_find_matches_a_dn_spelled_in_another_case(): void
    {
        $this->store('cn=Alice,dc=example,dc=com');

        self::assertNotNull($this->subject->find(new Dn('CN=ALICE,DC=EXAMPLE,DC=COM')));
    }

    public function test_find_returns_null_for_a_dn_that_is_not_stored(): void
    {
        self::assertNull($this->subject->find(new Dn('cn=Charlie,dc=example,dc=com')));
    }

    public function test_find_surfaces_a_linked_attribute_as_the_targets_current_dn(): void
    {
        $this->store('cn=Bob,dc=example,dc=com');
        $this->store('cn=Admins,dc=example,dc=com');
        $this->linkTogether(
            $this->fromContainer(PdoConnection::class)->pdo(),
            'cn=admins,dc=example,dc=com',
            'cn=bob,dc=example,dc=com',
        );

        self::assertSame(
            ['cn=Bob,dc=example,dc=com'],
            $this->subject->find(new Dn('cn=admins,dc=example,dc=com'))
                ?->get('member')
                ?->getValues(),
        );
    }

    public function test_find_bounds_a_linked_attribute_over_the_cap_under_the_range_it_holds(): void
    {
        $this->groupOf(5);

        $group = $this->subject->find(
            new Dn('cn=admins,dc=example,dc=com'),
            new EntryProjection(linkCap: 3),
        );

        self::assertSame(
            [
                'member;range=0-2' => [
                    'cn=User0,dc=example,dc=com',
                    'cn=User1,dc=example,dc=com',
                    'cn=User2,dc=example,dc=com',
                ],
            ],
            $this->linkedValuesOf($group),
        );
    }

    public function test_find_returns_a_linked_attribute_within_the_cap_under_its_own_name(): void
    {
        $this->groupOf(3);

        self::assertCount(
            3,
            $this->subject->find(
                new Dn('cn=admins,dc=example,dc=com'),
                new EntryProjection(linkCap: 3),
            )?->get('member')?->getValues() ?? [],
        );
    }

    public function test_find_returns_every_linked_value_when_unbounded(): void
    {
        $this->groupOf(5);

        self::assertCount(
            5,
            $this->subject->find(
                new Dn('cn=admins,dc=example,dc=com'),
                EntryProjection::unbounded(),
            )?->get('member')?->getValues() ?? [],
        );
    }

    public function test_exists_answers_whether_a_dn_is_stored(): void
    {
        $this->store('cn=Alice,dc=example,dc=com');

        self::assertTrue($this->subject->exists(new Dn('cn=alice,dc=example,dc=com')));
        self::assertFalse($this->subject->exists(new Dn('cn=bob,dc=example,dc=com')));
    }

    public function test_has_children_is_true_for_an_entry_with_one_beneath_it(): void
    {
        $this->store('dc=example,dc=com');
        $this->store('cn=Alice,dc=example,dc=com');

        self::assertTrue($this->subject->hasChildren(new Dn('dc=example,dc=com')));
    }

    public function test_has_children_is_false_for_a_leaf_entry(): void
    {
        $this->store('dc=example,dc=com');
        $this->store('cn=Alice,dc=example,dc=com');

        self::assertFalse($this->subject->hasChildren(new Dn('cn=alice,dc=example,dc=com')));
    }

    public function test_naming_contexts_are_the_entries_whose_parent_is_not_stored(): void
    {
        $this->store('dc=example,dc=com');
        $this->store('cn=Alice,dc=example,dc=com');
        $this->store('dc=other,dc=org');

        $contexts = array_map(
            static fn(Dn $dn): string => $dn->toString(),
            $this->subject->namingContexts(),
        );
        sort($contexts);

        self::assertSame(
            ['dc=example,dc=com', 'dc=other,dc=org'],
            $contexts,
        );
    }

    public function test_naming_contexts_are_empty_for_empty_storage(): void
    {
        self::assertSame(
            [],
            $this->subject->namingContexts(),
        );
    }

    public function test_a_slice_reads_the_values_it_names(): void
    {
        $this->groupOf(10);

        self::assertSame(
            ['member;range=4-6'],
            array_keys($this->slice('4-6', cap: 5)),
        );
        self::assertSame(
            [
                'cn=User4,dc=example,dc=com',
                'cn=User5,dc=example,dc=com',
                'cn=User6,dc=example,dc=com',
            ],
            $this->slice('4-6', cap: 5)['member;range=4-6'],
        );
    }

    public function test_a_slice_naming_one_position_reads_that_value_alone(): void
    {
        $this->groupOf(10);

        self::assertSame(
            ['member;range=1-1' => ['cn=User1,dc=example,dc=com']],
            $this->slice('1-1', cap: 5),
        );
    }

    public function test_a_slice_reaching_the_end_is_named_to_the_end(): void
    {
        $this->groupOf(10);

        self::assertSame(
            ['member;range=8-*'],
            array_keys($this->slice('8-*', cap: 5)),
        );
    }

    public function test_an_open_ended_slice_stops_at_the_cap(): void
    {
        $this->groupOf(10);
        $sliced = $this->slice('2-*', cap: 3);

        self::assertSame(
            ['member;range=2-4'],
            array_keys($sliced),
        );
        self::assertCount(3, $sliced['member;range=2-4']);
    }

    public function test_a_slice_past_everything_held_reads_nothing(): void
    {
        $this->groupOf(10);

        self::assertSame(
            [],
            $this->slice('50-*', cap: 5),
        );
    }

    /**
     * The subject is the adapter rather than schema enforcement, so its fixtures are not held to one.
     */
    protected function makeServerOptions(): ServerOptions
    {
        return TestServerOptions::sqlite();
    }

    /**
     * @return array<string, list<string>>
     */
    private function slice(
        string $range,
        int $cap,
    ): array {
        $window = LinkWindow::fromOption(new Option("range={$range}"));
        self::assertNotNull($window);

        return $this->linkedValuesOf($this->subject->find(
            new Dn('cn=admins,dc=example,dc=com'),
            new EntryProjection(
                linkCap: $cap,
                windows: ['member' => $window],
            ),
        ));
    }

    private function store(string $dn): void
    {
        $this->storage->store(new Entry(new Dn($dn)));
    }

    private function groupOf(int $members): void
    {
        $this->store('cn=Admins,dc=example,dc=com');

        for ($i = 0; $i < $members; $i++) {
            $this->store(sprintf('cn=User%d,dc=example,dc=com', $i));
            $this->linkTogether(
                $this->fromContainer(PdoConnection::class)->pdo(),
                'cn=admins,dc=example,dc=com',
                sprintf('cn=user%d,dc=example,dc=com', $i),
            );
        }
    }

    /**
     * @return array<string, list<string>>
     */
    private function linkedValuesOf(?Entry $entry): array
    {
        $values = [];

        foreach ($entry?->getAttributes() ?? [] as $attribute) {
            $values[$attribute->getDescription()] = array_values($attribute->getValues());
        }

        return $values;
    }
}
