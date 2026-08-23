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

namespace Tests\Unit\FreeDSx\Ldap\Sync\Consumer;

use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Result\EntryResult;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Utility\Uuid;
use FreeDSx\Ldap\Sync\Consumer\ChangeApplierInterface;
use FreeDSx\Ldap\Sync\Consumer\VerbatimStorageApplier;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Session;
use PHPUnit\Framework\TestCase;

final class VerbatimStorageApplierTest extends TestCase
{
    private const UUID_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

    private const UUID_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

    private const UUID_C = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';

    private InMemoryStorage $storage;

    private ChangeApplierInterface $subject;

    protected function setUp(): void
    {
        $this->storage = new InMemoryStorage();
        $this->subject = new VerbatimStorageApplier($this->storage);
    }

    public function test_an_add_stores_the_entry(): void
    {
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_ADD,
                $this->entry('cn=alice,dc=example,dc=com'),
            ),
            $this->refreshSession(),
        );

        self::assertTrue($this->exists('cn=alice,dc=example,dc=com'));
    }

    public function test_a_modify_replaces_the_stored_entry(): void
    {
        $session = $this->refreshSession();

        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_ADD,
                new Entry(
                    'cn=bob,dc=example,dc=com',
                    new Attribute('cn', 'bob'),
                    new Attribute('sn', 'Old'),
                ),
            ),
            $session,
        );
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_MODIFY,
                new Entry(
                    'cn=bob,dc=example,dc=com',
                    new Attribute('cn', 'bob'),
                    new Attribute('sn', 'New'),
                ),
            ),
            $session,
        );

        self::assertSame(
            'New',
            $this->value('cn=bob,dc=example,dc=com', 'sn'),
        );
    }

    public function test_a_delete_removes_the_entry(): void
    {
        $this->storage->store($this->entry('cn=carol,dc=example,dc=com'));

        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_DELETE,
                $this->entry('cn=carol,dc=example,dc=com'),
            ),
            $this->refreshSession(),
        );

        self::assertFalse($this->exists('cn=carol,dc=example,dc=com'));
    }

    public function test_reconcile_removes_locals_absent_from_the_present_phase(): void
    {
        foreach (['a' => self::UUID_A, 'b' => self::UUID_B, 'c' => self::UUID_C] as $cn => $uuid) {
            $this->storage->store($this->entry("cn=$cn,dc=example,dc=com", $uuid));
        }

        $session = $this->refreshSession();
        $this->subject->beginRefresh();
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_ADD,
                $this->entry('cn=a,dc=example,dc=com', self::UUID_A),
            ),
            $session,
        );
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_ADD,
                $this->entry('cn=b,dc=example,dc=com', self::UUID_B),
            ),
            $session,
        );
        $this->subject->reconcile();

        self::assertTrue($this->exists('cn=a,dc=example,dc=com'));
        self::assertTrue($this->exists('cn=b,dc=example,dc=com'));
        self::assertFalse($this->exists('cn=c,dc=example,dc=com'));
    }

    /**
     * A refresh presents the entry only at its new DN, so the sweep is what removes the old one.
     */
    public function test_reconcile_removes_the_old_dn_of_an_entry_presented_elsewhere(): void
    {
        $this->storage->store($this->entry('cn=old,dc=example,dc=com'));

        $session = $this->refreshSession();
        $this->subject->beginRefresh();
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_ADD,
                $this->entry('cn=new,dc=example,dc=com'),
            ),
            $session,
        );
        $this->subject->reconcile();

        self::assertFalse($this->exists('cn=old,dc=example,dc=com'));
        self::assertTrue($this->exists('cn=new,dc=example,dc=com'));
    }

    /**
     * RFC 4533 §3.6 keys entries by entryUUID, so the same UUID arriving at a new DN is a move, not a second entry.
     */
    public function test_a_move_during_persist_relocates_rather_than_duplicating(): void
    {
        $this->storage->store($this->entry('cn=old,dc=example,dc=com'));

        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_MODIFY,
                $this->entry('cn=new,dc=example,dc=com'),
            ),
            $this->persistSession(),
        );

        self::assertFalse(
            $this->exists('cn=old,dc=example,dc=com'),
            'The entry must not be left behind at the DN it moved from.',
        );
        self::assertTrue($this->exists('cn=new,dc=example,dc=com'));
    }

    public function test_a_modify_at_the_same_dn_replaces_in_place(): void
    {
        $this->storage->store($this->entry('cn=alice,dc=example,dc=com'));

        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_MODIFY,
                new Entry(
                    'cn=alice,dc=example,dc=com',
                    new Attribute('cn', 'x'),
                    new Attribute('sn', 'Changed'),
                    new Attribute('entryUUID', self::UUID_A),
                ),
            ),
            $this->persistSession(),
        );

        self::assertTrue($this->exists('cn=alice,dc=example,dc=com'));
        self::assertSame(
            'Changed',
            $this->value('cn=alice,dc=example,dc=com', 'sn'),
        );
    }

    /**
     * A narrowed selection strips entryUUID from the entry, so the applier stamps the control's copy on to keep the
     * local entry correlatable.
     */
    public function test_an_entry_whose_selection_dropped_the_uuid_is_still_correlatable(): void
    {
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_ADD,
                new Entry(
                    'cn=old,dc=example,dc=com',
                    new Attribute('cn', 'x'),
                ),
            ),
            $this->persistSession(),
        );

        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_MODIFY,
                $this->entry('cn=new,dc=example,dc=com'),
            ),
            $this->persistSession(),
        );

        self::assertFalse($this->exists('cn=old,dc=example,dc=com'));
        self::assertTrue($this->exists('cn=new,dc=example,dc=com'));
    }

    public function test_begin_refresh_clears_the_previous_present_set(): void
    {
        $session = $this->refreshSession();

        $this->subject->beginRefresh();
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_ADD,
                $this->entry('cn=a,dc=example,dc=com'),
            ),
            $session,
        );

        // A second refresh presents nothing; the first refresh's present-set must not protect the entry.
        $this->subject->beginRefresh();
        $this->subject->reconcile();

        self::assertFalse($this->exists('cn=a,dc=example,dc=com'));
    }

    /**
     * @param ?string $uuid The entry's identity; two DNs sharing one are the same entry, moved.
     */
    private function entry(
        string $dn,
        ?string $uuid = null,
    ): Entry {
        return new Entry(
            $dn,
            new Attribute('cn', 'x'),
            new Attribute('entryUUID', $uuid ?? self::UUID_A),
        );
    }

    private function syncResult(
        int $state,
        Entry $entry,
    ): SyncEntryResult {
        $message = new LdapMessageResponse(
            1,
            new SearchResultEntry($entry),
            new SyncStateControl(
                $state,
                Uuid::toBinary($entry->get('entryUUID')?->firstValue() ?? self::UUID_A),
            ),
        );

        return new SyncEntryResult(new EntryResult($message));
    }

    private function refreshSession(): Session
    {
        return new Session(
            Session::MODE_LISTEN,
            null,
        );
    }

    /**
     * Past the refresh, where nothing sweeps a stale copy afterwards.
     */
    private function persistSession(): Session
    {
        return $this->refreshSession()
            ->markRefreshComplete();
    }

    private function exists(string $dn): bool
    {
        return $this->storage->find((new Dn($dn))->normalize()) !== null;
    }

    private function value(
        string $dn,
        string $attribute,
    ): ?string {
        $entry = $this->storage->find((new Dn($dn))->normalize());

        if ($entry === null) {
            return null;
        }

        $values = $entry->get($attribute)?->getValues() ?? [];

        return $values[0] ?? null;
    }
}
