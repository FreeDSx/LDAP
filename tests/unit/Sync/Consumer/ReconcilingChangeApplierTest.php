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
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Search\Result\EntryResult;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;
use FreeDSx\Ldap\Sync\Consumer\ChangeApplierInterface;
use FreeDSx\Ldap\Sync\Consumer\ReconcilingChangeApplier;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;
use FreeDSx\Ldap\Sync\Session;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ReconcilingChangeApplierTest extends TestCase
{
    private const DN = 'cn=alice,dc=example,dc=com';

    private ChangeApplierInterface&MockObject $baseApplier;

    private ReplicaPasswordStateStoreInterface&MockObject $passwordStateStore;

    private ReconcilingChangeApplier $subject;

    protected function setUp(): void
    {
        $this->baseApplier = $this->createMock(ChangeApplierInterface::class);
        $this->passwordStateStore = $this->createMock(ReplicaPasswordStateStoreInterface::class);
        $this->subject = new ReconcilingChangeApplier(
            $this->baseApplier,
            $this->passwordStateStore,
        );
    }

    public function test_begin_refresh_delegates_to_the_base_applier(): void
    {
        $this->baseApplier
            ->expects(self::once())
            ->method('beginRefresh');

        $this->subject->beginRefresh();
    }

    public function test_reconcile_delegates_to_the_base_applier(): void
    {
        $this->baseApplier
            ->expects(self::once())
            ->method('reconcile');

        $this->subject->reconcile();
    }

    public function test_apply_delegates_the_result_to_the_base_applier(): void
    {
        $result = $this->syncResult(
            SyncStateControl::STATE_ADD,
            $this->entry(),
        );
        $session = $this->session();

        $this->baseApplier
            ->expects(self::once())
            ->method('apply')
            ->with(
                $result,
                $session,
            );

        $this->subject->apply(
            $result,
            $session,
        );
    }

    public function test_an_add_reconciles_the_local_state_against_the_entry(): void
    {
        $this->passwordStateStore
            ->expects(self::once())
            ->method('discardIfSuperseded')
            ->with(
                self::callback(static fn(Dn $dn): bool => $dn->toString() === (new Dn(self::DN))->normalize()->toString()),
                self::callback(static fn(UserPasswordState $state): bool => $state->isLocked()),
            );

        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_ADD,
                $this->lockedEntry(),
            ),
            $this->session(),
        );
    }

    public function test_a_modify_reconciles_the_local_state_against_the_entry(): void
    {
        $this->passwordStateStore
            ->expects(self::once())
            ->method('discardIfSuperseded');

        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_MODIFY,
                $this->lockedEntry(),
            ),
            $this->session(),
        );
    }

    public function test_a_present_marker_does_not_reconcile(): void
    {
        $this->passwordStateStore
            ->expects(self::never())
            ->method('discardIfSuperseded');
        $this->passwordStateStore
            ->expects(self::never())
            ->method('discard');

        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_PRESENT,
                $this->entry(),
            ),
            $this->session(),
        );
    }

    public function test_a_delete_discards_the_local_state_outright(): void
    {
        $this->passwordStateStore
            ->expects(self::never())
            ->method('discardIfSuperseded');
        $this->passwordStateStore
            ->expects(self::once())
            ->method('discard')
            ->with(self::callback(static fn(Dn $dn): bool => $dn->toString() === (new Dn(self::DN))->normalize()->toString()));

        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_DELETE,
                $this->entry(),
            ),
            $this->session(),
        );
    }

    public function test_an_id_set_discards_the_local_state_of_every_dn_it_removed(): void
    {
        $removed = [
            new Dn(self::DN),
            new Dn('cn=bob,dc=example,dc=com'),
        ];
        $idSet = $this->createMock(SyncIdSetResult::class);
        $session = $this->session();

        $this->baseApplier
            ->expects(self::once())
            ->method('applyIdSet')
            ->with(
                $idSet,
                $session,
            )
            ->willReturn($removed);
        $this->passwordStateStore
            ->expects(self::exactly(2))
            ->method('discard');

        self::assertSame(
            $removed,
            $this->subject->applyIdSet(
                $idSet,
                $session,
            ),
        );
    }

    public function test_an_id_set_that_removed_nothing_discards_no_local_state(): void
    {
        $this->baseApplier
            ->method('applyIdSet')
            ->willReturn([]);
        $this->passwordStateStore
            ->expects(self::never())
            ->method('discard');

        $this->subject->applyIdSet(
            $this->createMock(SyncIdSetResult::class),
            $this->session(),
        );
    }

    private function entry(): Entry
    {
        return new Entry(
            self::DN,
            new Attribute('cn', 'alice'),
        );
    }

    private function lockedEntry(): Entry
    {
        return new Entry(
            self::DN,
            new Attribute('cn', 'alice'),
            new Attribute(
                PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
                '20260520120000Z',
            ),
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
                'uuid-' . $entry->getDn()->toString(),
            ),
        );

        return new SyncEntryResult(new EntryResult($message));
    }

    private function session(): Session
    {
        return new Session(
            Session::MODE_LISTEN,
            null,
        );
    }
}
