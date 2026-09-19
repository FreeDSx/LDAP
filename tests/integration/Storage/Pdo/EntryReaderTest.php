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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoStorage;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class EntryReaderTest extends TestCase
{
    use ServerContainerTrait;

    private EntryReader $subject;

    private PdoStorage $storage;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(EntryReader::class);
        $this->storage = $this->fromContainer(PdoStorage::class);
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

    /**
     * The subject is the adapter rather than schema enforcement, so its fixtures are not held to one.
     */
    protected function makeServerOptions(): ServerOptions
    {
        return TestServerOptions::sqlite();
    }

    private function store(string $dn): void
    {
        $this->storage->store(new Entry(new Dn($dn)));
    }

    /**
     * Writes a member link straight into the table, since the write path does not divert values into it yet.
     */
    private function linkTogether(
        string $ownerLcDn,
        string $targetLcDn,
    ): void {
        $this->fromContainer(PdoConnection::class)
            ->pdo()
            ->prepare(
                'INSERT INTO entry_attribute_links (owner_entry_id, attr_name_lower, target_entry_id, target_uid)
                 SELECT o.entry_id, ?, t.entry_id, \'\'
                 FROM entries o, entries t
                 WHERE o.lc_dn = ? AND t.lc_dn = ?',
            )
            ->execute([
                'member',
                $ownerLcDn,
                $targetLcDn,
            ]);
    }
}
