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
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ListEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;

/**
 * Shared renameSubtree() contract, so every adapter moves a subtree the same way.
 *
 * @mixin \PHPUnit\Framework\TestCase
 */
trait SubtreeRenameStorageContractTests
{
    public function test_renaming_a_subtree_moves_the_base_entry(): void
    {
        $container = $this->renameContainer();
        $this->renamePeopleToStaff($container);

        self::assertNull($this->storedEntry($container, 'ou=people,dc=foo,dc=bar'));
        self::assertSame(
            'ou=Staff,dc=foo,dc=bar',
            $this->storedEntry($container, 'ou=staff,dc=foo,dc=bar')?->getDn()->toString(),
        );
    }

    public function test_renaming_a_subtree_moves_every_child(): void
    {
        $container = $this->renameContainer();
        $this->renamePeopleToStaff($container);

        self::assertSame(
            [
                'cn=Alice,ou=Staff,dc=foo,dc=bar',
                'cn=Bob,ou=Staff,dc=foo,dc=bar',
                'cn=dave,ou=staff,dc=foo,dc=bar',
            ],
            $this->storedDnsUnder(
                $container,
                'ou=staff,dc=foo,dc=bar',
            ),
        );
    }

    public function test_renaming_a_subtree_moves_a_descendant_nested_below_a_child(): void
    {
        $container = $this->renameContainer();
        $this->renamePeopleToStaff($container);

        self::assertSame(
            'cn=Laptop,cn=Alice,ou=Staff,dc=foo,dc=bar',
            $this->storedEntry($container, 'cn=laptop,cn=alice,ou=staff,dc=foo,dc=bar')?->getDn()->toString(),
        );
    }

    public function test_renaming_a_subtree_reparents_the_children_it_moves(): void
    {
        $container = $this->renameContainer();
        $this->renamePeopleToStaff($container);

        $reader = $container->get(ReadEntryInterface::class);

        self::assertTrue($reader->hasChildren(new Dn('ou=staff,dc=foo,dc=bar')));
        self::assertFalse($reader->hasChildren(new Dn('ou=people,dc=foo,dc=bar')));
    }

    public function test_renaming_a_subtree_leaves_entries_outside_it_alone(): void
    {
        $container = $this->renameContainer();
        $this->renamePeopleToStaff($container);

        self::assertSame(
            'cn=Carol,ou=Groups,dc=foo,dc=bar',
            $this->storedEntry($container, 'cn=carol,ou=groups,dc=foo,dc=bar')?->getDn()->toString(),
        );
    }

    public function test_renaming_a_subtree_keeps_the_attributes_of_a_moved_entry(): void
    {
        $container = $this->renameContainer();
        $this->renamePeopleToStaff($container);

        self::assertSame(
            ['Alice'],
            $this->storedEntry($container, 'cn=alice,ou=staff,dc=foo,dc=bar')?->get('cn')?->getValues(),
        );
    }

    public function test_renaming_a_subtree_canonicalizes_a_descendant_that_spells_the_source_differently(): void
    {
        $container = $this->renameContainer();
        $this->renamePeopleToStaff($container);

        self::assertSame(
            'cn=dave,ou=staff,dc=foo,dc=bar',
            $this->storedEntry($container, 'cn=dave,ou=staff,dc=foo,dc=bar')?->getDn()->toString(),
        );
    }

    public function test_renaming_a_subtree_slices_multibyte_dns_on_character_boundaries(): void
    {
        $container = $this->makeRenameContainer(
            new Entry(new Dn('dc=foo,dc=bar')),
            new Entry(new Dn('ou=Москва,dc=foo,dc=bar')),
            new Entry(new Dn('cn=Zoë,ou=Москва,dc=foo,dc=bar')),
        );

        $container->get(WriteEntryInterface::class)->renameSubtree(
            new Dn('ou=москва,dc=foo,dc=bar'),
            new Dn('ou=Ω,dc=foo,dc=bar'),
        );

        self::assertSame(
            'cn=Zoë,ou=Ω,dc=foo,dc=bar',
            $this->storedEntry($container, 'cn=zoë,ou=ω,dc=foo,dc=bar')?->getDn()->toString(),
        );
    }

    public function test_renaming_a_subtree_that_does_not_exist_changes_nothing(): void
    {
        $container = $this->renameContainer();

        $container->get(WriteEntryInterface::class)->renameSubtree(
            new Dn('ou=missing,dc=foo,dc=bar'),
            new Dn('ou=Staff,dc=foo,dc=bar'),
        );

        self::assertNull($this->storedEntry($container, 'ou=staff,dc=foo,dc=bar'));
        self::assertNotNull($this->storedEntry($container, 'cn=alice,ou=people,dc=foo,dc=bar'));
    }

    public function test_renaming_a_subtree_into_its_own_subtree_is_refused(): void
    {
        $container = $this->renameContainer();

        $this->expectException(InvalidArgumentException::class);

        $container->get(WriteEntryInterface::class)->renameSubtree(
            new Dn('ou=people,dc=foo,dc=bar'),
            new Dn('ou=Staff,ou=people,dc=foo,dc=bar'),
        );
    }

    /**
     * @param Entry ...$entries Seeded before the rename runs.
     * @return Container the graph holding the seeded entries, which every storage contract resolves from
     */
    abstract protected function makeRenameContainer(Entry ...$entries): Container;

    private function renameContainer(): Container
    {
        return $this->makeRenameContainer(
            new Entry(new Dn('dc=foo,dc=bar')),
            new Entry(new Dn('ou=People,dc=foo,dc=bar')),
            new Entry(new Dn('ou=Groups,dc=foo,dc=bar')),
            new Entry(
                new Dn('cn=Alice,ou=People,dc=foo,dc=bar'),
                new Attribute('cn', 'Alice'),
            ),
            new Entry(new Dn('cn=Bob,ou=People,dc=foo,dc=bar')),
            new Entry(new Dn('cn=Laptop,cn=Alice,ou=People,dc=foo,dc=bar')),
            // Stored with a spelling of the parent that the base entry does not carry.
            new Entry(new Dn('cn=dave,OU=people,dc=foo,dc=bar')),
            new Entry(new Dn('cn=Carol,ou=Groups,dc=foo,dc=bar')),
        );
    }

    private function renamePeopleToStaff(Container $container): void
    {
        $container->get(WriteEntryInterface::class)->renameSubtree(
            new Dn('ou=people,dc=foo,dc=bar'),
            new Dn('ou=Staff,dc=foo,dc=bar'),
        );
    }

    private function storedEntry(
        Container $container,
        string $dn,
    ): ?Entry {
        return $container->get(ReadEntryInterface::class)
            ->find(new Dn($dn));
    }

    /**
     * @return list<string>
     */
    private function storedDnsUnder(
        Container $container,
        string $baseDn,
    ): array {
        $dns = [];

        $stream = $container->get(ListEntryInterface::class)
            ->list(StorageListOptions::matchAll(new Dn($baseDn), false));
        foreach ($stream->entries() as $entry) {
            $dns[] = $entry->getDn()->toString();
        }
        sort($dns);

        return $dns;
    }
}
