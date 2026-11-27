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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter;

use DateTimeImmutable;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Definition\GeneralizedTime;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaForwardState;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class PdoReplicaPasswordStateStoreTest extends TestCase
{
    use ServerContainerTrait;

    private const DN = 'cn=foo,dc=example,dc=com';

    private const UUID = '3f2b9c1e-7a4d-4e8b-9c6f-1d2e3f4a5b6c';

    private const OTHER_UUID = '8a7b6c5d-4e3f-4a2b-9c1d-0e9f8a7b6c5d';

    private const PASSWORD_ONE = '20260101000000.250000Z';

    private const PASSWORD_TWO = '20260102000000.500000Z';

    private WriteEntryInterface $storage;

    private ReplicaPasswordStateStoreInterface $subject;

    /**
     * Both come from one container, so the store and the storage share the connection they are assembled on.
     *
     * State rows are foreign-keyed to the entry they describe, so the entry has to exist before any state does.
     */
    protected function setUp(): void
    {
        $this->storage = $this->fromContainer(WriteEntryInterface::class);
        $this->subject = $this->fromContainer(ReplicaPasswordStateStoreInterface::class);

        $this->storeEntry(self::UUID);
    }

    public function test_load_is_empty_when_nothing_was_recorded(): void
    {
        self::assertTrue($this->subject->load(self::UUID)->isEmpty());
    }

    public function test_apply_persists_and_reloads_state(): void
    {
        $this->applyChanges(OperationalChanges::of(Change::replace(
            PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
            '20260520120000Z',
        )));

        self::assertTrue(
            $this->subject
                ->load(self::UUID)
                ->toUserPasswordState(new Dn(self::DN))
                ->isLocked(),
        );
    }

    public function test_a_write_against_the_same_password_merges_into_the_state(): void
    {
        $this->applyChanges(
            $this->failureAt('20260520120000.100000Z'),
            GeneralizedTime::parse(self::PASSWORD_ONE),
        );
        $this->applyChanges(
            $this->lockAt('20260520120001Z'),
            GeneralizedTime::parse(self::PASSWORD_ONE),
        );

        self::assertEquals(
            [
                PasswordPolicyOid::NAME_PWD_FAILURE_TIME => ['20260520120000.100000Z'],
                PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME => ['20260520120001Z'],
                PasswordPolicyOid::NAME_PWD_CHANGED_TIME => [self::PASSWORD_ONE],
            ],
            $this->subject->load(self::UUID)->toArray(),
        );
    }

    public function test_a_write_against_another_password_replaces_the_whole_state(): void
    {
        $this->applyChanges(
            $this->lockAt('20260520120000Z'),
            GeneralizedTime::parse(self::PASSWORD_ONE),
        );
        $this->applyChanges(
            $this->failureAt('20260520130000.100000Z'),
            GeneralizedTime::parse(self::PASSWORD_TWO),
        );

        self::assertEquals(
            [
                PasswordPolicyOid::NAME_PWD_FAILURE_TIME => ['20260520130000.100000Z'],
                PasswordPolicyOid::NAME_PWD_CHANGED_TIME => [self::PASSWORD_TWO],
            ],
            $this->subject->load(self::UUID)->toArray(),
        );
    }

    public function test_a_write_against_an_older_password_is_dropped(): void
    {
        $this->applyChanges(
            $this->failureAt('20260520130000.100000Z'),
            GeneralizedTime::parse(self::PASSWORD_TWO),
        );
        $this->applyChanges(
            $this->failureAt('20260520130001.100000Z'),
            GeneralizedTime::parse(self::PASSWORD_ONE),
        );

        self::assertEquals(
            [
                PasswordPolicyOid::NAME_PWD_FAILURE_TIME => ['20260520130000.100000Z'],
                PasswordPolicyOid::NAME_PWD_CHANGED_TIME => [self::PASSWORD_TWO],
            ],
            $this->subject->load(self::UUID)->toArray(),
        );
    }

    public function test_a_write_without_a_password_version_is_dropped_once_the_state_has_one(): void
    {
        $this->applyChanges(
            $this->failureAt('20260520130000.100000Z'),
            GeneralizedTime::parse(self::PASSWORD_ONE),
        );
        $this->applyChanges($this->failureAt('20260520130001.100000Z'));

        self::assertEquals(
            [
                PasswordPolicyOid::NAME_PWD_FAILURE_TIME => ['20260520130000.100000Z'],
                PasswordPolicyOid::NAME_PWD_CHANGED_TIME => [self::PASSWORD_ONE],
            ],
            $this->subject->load(self::UUID)->toArray(),
        );
    }

    public function test_apply_reset_removes_the_row(): void
    {
        $this->applyFailure('20260520120000Z');

        $this->applyChanges(OperationalChanges::of(Change::reset(PasswordPolicyOid::NAME_PWD_FAILURE_TIME)));

        self::assertTrue($this->subject->load(self::UUID)->isEmpty());
    }

    public function test_local_state_survives_a_verbatim_entry_store(): void
    {
        $this->applyChanges(OperationalChanges::of(Change::replace(
            PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
            '20260520120000Z',
        )));

        $this->storeEntry(self::UUID);

        self::assertTrue(
            $this->subject
                ->load(self::UUID)
                ->toUserPasswordState(new Dn(self::DN))
                ->isLocked(),
        );
    }

    public function test_local_state_follows_the_entry_through_a_rename(): void
    {
        $this->applyFailure('20260520120000Z');

        $this->storage->renameSubtree(
            new Dn(self::DN),
            new Dn('cn=bar,dc=example,dc=com'),
        );

        self::assertSame(
            'cn=bar,dc=example,dc=com',
            $this->subject->listUnforwarded()[0]->dn->toString(),
        );
    }

    public function test_a_different_entry_stored_at_the_dn_takes_none_of_the_replaced_entrys_state(): void
    {
        $this->applyFailure('20260520120000Z');

        $this->storeEntry(self::OTHER_UUID);

        self::assertTrue($this->subject->load(self::OTHER_UUID)->isEmpty());
        self::assertSame(
            [],
            $this->subject->listUnforwarded(),
        );
    }

    public function test_recording_for_an_entry_storage_no_longer_holds_records_nothing(): void
    {
        $this->subject->atomicMutate(
            self::OTHER_UUID,
            null,
            static fn(): OperationalChanges => OperationalChanges::of(Change::replace(
                PasswordPolicyOid::NAME_PWD_FAILURE_TIME,
                '20260520120000Z',
            )),
        );

        self::assertSame(
            [],
            $this->subject->listUnforwarded(),
        );
    }

    public function test_a_recorded_change_becomes_a_pending_forward_under_its_entry_uuid(): void
    {
        $this->applyFailure('20260520120000Z');

        $pending = $this->subject->listUnforwarded();

        self::assertCount(
            1,
            $pending,
        );
        self::assertSame(
            self::UUID,
            $pending[0]->uuid,
        );
        self::assertSame(
            self::DN,
            $pending[0]->dn->toString(),
        );
        self::assertSame(
            1,
            $pending[0]->sequence,
        );
    }

    public function test_marking_forwarded_clears_the_pending_entry(): void
    {
        $this->applyFailure('20260520120000Z');

        $this->subject->markForwarded(
            self::UUID,
            1,
        );

        self::assertSame(
            [],
            $this->subject->listUnforwarded(),
        );
    }

    public function test_marking_another_entry_uuid_forwarded_leaves_this_one_pending(): void
    {
        $this->applyFailure('20260520120000Z');

        $this->subject->markForwarded(
            self::OTHER_UUID,
            1,
        );

        self::assertCount(
            1,
            $this->subject->listUnforwarded(),
        );
    }

    public function test_marking_a_stale_sequence_leaves_a_newer_change_pending(): void
    {
        $this->applyFailure('20260520120000Z');
        $this->applyFailure('20260520120500Z');

        $this->subject->markForwarded(
            self::UUID,
            1,
        );

        $pending = $this->subject->listUnforwarded();

        self::assertCount(
            1,
            $pending,
        );
        self::assertSame(
            2,
            $pending[0]->sequence,
        );
    }

    public function test_discard_drops_local_state_when_the_entry_is_authoritatively_locked(): void
    {
        $this->applyFailure('20260520120000Z');

        $this->subject->discardIfSuperseded(
            self::UUID,
            new UserPasswordState(accountLockedAt: GeneralizedTime::parse('20260520120500Z')),
        );

        self::assertTrue($this->subject->load(self::UUID)->isEmpty());
    }

    public function test_discard_drops_local_state_when_a_success_is_newer_than_the_failure(): void
    {
        $this->applyFailure('20260520120000Z');

        $this->subject->discardIfSuperseded(
            self::UUID,
            new UserPasswordState(lastSuccess: GeneralizedTime::parse('20260520120500Z')),
        );

        self::assertTrue($this->subject->load(self::UUID)->isEmpty());
    }

    public function test_discard_keeps_sub_threshold_state_the_entry_has_not_reflected(): void
    {
        $this->applyFailure('20260520120000Z');

        $this->subject->discardIfSuperseded(
            self::UUID,
            new UserPasswordState(),
        );

        self::assertFalse($this->subject->load(self::UUID)->isEmpty());
    }

    public function test_a_forward_acknowledged_after_a_discard_leaves_the_next_write_pending(): void
    {
        $this->applyFailure('20260520120000Z');
        $this->subject->discardIfSuperseded(
            self::UUID,
            new UserPasswordState(accountLockedAt: GeneralizedTime::parse('20260520120500Z')),
        );
        $this->applyFailure('20260520120600Z');

        $this->subject->markForwarded(
            self::UUID,
            1,
        );
        $pending = $this->subject->listUnforwarded();

        self::assertCount(
            1,
            $pending,
        );
        self::assertSame(
            ['20260520120600Z'],
            $pending[0]->state->toArray()[PasswordPolicyOid::NAME_PWD_FAILURE_TIME] ?? [],
        );
    }

    public function test_a_discard_after_the_forward_was_acknowledged_lets_the_subject_start_afresh(): void
    {
        $this->applyFailure('20260520120000Z');
        $this->subject->markForwarded(
            self::UUID,
            1,
        );
        $this->subject->discardIfSuperseded(
            self::UUID,
            new UserPasswordState(accountLockedAt: GeneralizedTime::parse('20260520120500Z')),
        );

        $this->applyFailure('20260520120600Z');

        self::assertSame(
            [1],
            array_map(
                static fn(ReplicaForwardState $pending): int => $pending->sequence,
                $this->subject->listUnforwarded(),
            ),
        );
    }

    public function test_a_discard_leaves_nothing_to_forward(): void
    {
        $this->applyFailure('20260520120000Z');

        $this->subject->discardIfSuperseded(
            self::UUID,
            new UserPasswordState(accountLockedAt: GeneralizedTime::parse('20260520120500Z')),
        );

        self::assertSame(
            [],
            $this->subject->listUnforwarded(),
        );
    }

    public function test_discard_is_a_noop_for_an_unknown_subject(): void
    {
        $this->subject->discardIfSuperseded(
            self::OTHER_UUID,
            new UserPasswordState(accountLockedAt: GeneralizedTime::parse('20260520120500Z')),
        );

        self::assertTrue($this->subject->load(self::OTHER_UUID)->isEmpty());
    }

    public function test_removing_the_entry_removes_its_state(): void
    {
        $this->applyFailure('20260520120000Z');

        $this->storage->remove(new Dn(self::DN));

        self::assertSame(
            [],
            $this->subject->listUnforwarded(),
        );
    }

    public function test_a_change_after_forwarding_re_lists_at_a_higher_sequence(): void
    {
        $this->applyFailure('20260520120000Z');
        $this->subject->markForwarded(
            self::UUID,
            1,
        );
        $this->applyFailure('20260520120500Z');

        $pending = $this->subject->listUnforwarded();

        self::assertCount(
            1,
            $pending,
        );
        self::assertSame(
            2,
            $pending[0]->sequence,
        );
    }

    public function test_discard_keeps_local_state_when_the_success_predates_the_failure(): void
    {
        $this->applyFailure('20260520120000Z');

        $this->subject->discardIfSuperseded(
            self::UUID,
            new UserPasswordState(lastSuccess: GeneralizedTime::parse('20260520115500Z')),
        );

        self::assertFalse($this->subject->load(self::UUID)->isEmpty());
    }

    protected function makeServerOptions(): ServerOptions
    {
        return TestServerOptions::sqlite();
    }

    private function storeEntry(string $uuid): void
    {
        $this->storage->store(new Entry(
            new Dn(self::DN),
            new Attribute('cn', 'foo'),
            new Attribute('entryUUID', $uuid),
        ));
    }

    private function applyFailure(string $time): void
    {
        $this->applyChanges(OperationalChanges::of(Change::replace(
            PasswordPolicyOid::NAME_PWD_FAILURE_TIME,
            $time,
        )));
    }

    private function failureAt(string $time): OperationalChanges
    {
        return OperationalChanges::of(Change::replace(
            PasswordPolicyOid::NAME_PWD_FAILURE_TIME,
            $time,
        ));
    }

    private function lockAt(string $time): OperationalChanges
    {
        return OperationalChanges::of(Change::replace(
            PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
            $time,
        ));
    }

    private function applyChanges(
        OperationalChanges $changes,
        ?DateTimeImmutable $version = null,
    ): void {
        $this->subject->atomicMutate(
            self::UUID,
            $version,
            static fn(): OperationalChanges => $changes,
        );
    }
}
