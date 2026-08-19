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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Definition\GeneralizedTime;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoTransactor;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoStatementPool;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\SharedPdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoReplicaPasswordStateStore;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoStorage;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;
use PDO;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Backend\Storage\PdoStorageFactoryTrait;

final class PdoReplicaPasswordStateStoreTest extends TestCase
{
    use PdoStorageFactoryTrait;

    private const DN = 'cn=foo,dc=example,dc=com';

    private PDO $pdo;

    private PdoStorage $storage;

    private ReplicaPasswordStateStoreInterface $subject;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        PdoStorage::initialize(
            $this->pdo,
            new SqliteDialect(),
        );
        $provider = new SharedPdoConnectionProvider(
            $this->pdo,
            fn(): PDO => $this->pdo,
        );
        $this->storage = self::makePdoStorage($provider);
        $this->subject = new PdoReplicaPasswordStateStore(
            new PdoTransactor(
                $provider,
                new SqliteDialect(),
            ),
            new SqliteDialect(),
            new PdoStatementPool($provider),
        );
    }

    public function test_load_is_empty_when_nothing_was_recorded(): void
    {
        self::assertTrue($this->subject->load(new Dn(self::DN))->isEmpty());
    }

    public function test_apply_persists_and_reloads_state(): void
    {
        $this->applyChanges(
            new Dn(self::DN),
            OperationalChanges::of(Change::replace(
                PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
                '20260520120000Z',
            )),
        );

        self::assertTrue(
            $this->subject
                ->load(new Dn(self::DN))
                ->toUserPasswordState(new Dn(self::DN))
                ->isLocked(),
        );
    }

    public function test_apply_reset_removes_the_row(): void
    {
        $dn = new Dn(self::DN);
        $this->applyChanges(
            $dn,
            OperationalChanges::of(Change::replace(
                PasswordPolicyOid::NAME_PWD_FAILURE_TIME,
                '20260520120000Z',
            )),
        );

        $this->applyChanges(
            $dn,
            OperationalChanges::of(Change::reset(PasswordPolicyOid::NAME_PWD_FAILURE_TIME)),
        );

        self::assertTrue($this->subject->load($dn)->isEmpty());
    }

    public function test_local_state_survives_a_verbatim_entry_store(): void
    {
        $dn = new Dn(self::DN);
        $this->applyChanges(
            $dn,
            OperationalChanges::of(Change::replace(
                PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
                '20260520120000Z',
            )),
        );

        $this->storage->store(new Entry(
            $dn,
            new Attribute('cn', 'foo'),
        ));

        self::assertTrue(
            $this->subject
                ->load($dn)
                ->toUserPasswordState($dn)
                ->isLocked(),
        );
    }

    public function test_a_recorded_change_becomes_a_pending_forward(): void
    {
        $this->applyFailure('20260520120000Z');

        $pending = $this->subject->listUnforwarded();

        self::assertCount(
            1,
            $pending,
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
            new Dn(self::DN),
            1,
        );

        self::assertSame(
            [],
            $this->subject->listUnforwarded(),
        );
    }

    public function test_marking_a_stale_sequence_leaves_a_newer_change_pending(): void
    {
        $this->applyFailure('20260520120000Z');
        $this->applyFailure('20260520120500Z');

        $this->subject->markForwarded(
            new Dn(self::DN),
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
            new Dn(self::DN),
            new UserPasswordState(accountLockedAt: GeneralizedTime::parse('20260520120500Z')),
        );

        self::assertTrue($this->subject->load(new Dn(self::DN))->isEmpty());
    }

    public function test_discard_drops_local_state_when_a_success_is_newer_than_the_failure(): void
    {
        $this->applyFailure('20260520120000Z');

        $this->subject->discardIfSuperseded(
            new Dn(self::DN),
            new UserPasswordState(lastSuccess: GeneralizedTime::parse('20260520120500Z')),
        );

        self::assertTrue($this->subject->load(new Dn(self::DN))->isEmpty());
    }

    public function test_discard_keeps_sub_threshold_state_the_entry_has_not_reflected(): void
    {
        $this->applyFailure('20260520120000Z');

        $this->subject->discardIfSuperseded(
            new Dn(self::DN),
            new UserPasswordState(),
        );

        self::assertFalse($this->subject->load(new Dn(self::DN))->isEmpty());
    }

    public function test_discard_is_a_noop_for_an_unknown_subject(): void
    {
        $this->subject->discardIfSuperseded(
            new Dn(self::DN),
            new UserPasswordState(accountLockedAt: GeneralizedTime::parse('20260520120500Z')),
        );

        self::assertTrue($this->subject->load(new Dn(self::DN))->isEmpty());
    }

    public function test_discard_removes_state_unconditionally(): void
    {
        $this->applyFailure('20260520120000Z');

        $this->subject->discard(new Dn(self::DN));

        self::assertTrue($this->subject->load(new Dn(self::DN))->isEmpty());
    }

    public function test_discard_of_an_unknown_subject_is_a_noop(): void
    {
        $this->subject->discard(new Dn(self::DN));

        self::assertTrue($this->subject->load(new Dn(self::DN))->isEmpty());
    }

    public function test_a_change_after_forwarding_re_lists_at_a_higher_sequence(): void
    {
        $this->applyFailure('20260520120000Z');
        $this->subject->markForwarded(
            new Dn(self::DN),
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
            new Dn(self::DN),
            new UserPasswordState(lastSuccess: GeneralizedTime::parse('20260520115500Z')),
        );

        self::assertFalse($this->subject->load(new Dn(self::DN))->isEmpty());
    }

    public function test_state_is_keyed_by_the_canonical_dn(): void
    {
        $this->applyChanges(
            new Dn('CN=Foo,DC=Example,DC=Com'),
            OperationalChanges::of(Change::replace(
                PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
                '20260520120000Z',
            )),
        );

        self::assertFalse($this->subject->load(new Dn(self::DN))->isEmpty());
    }

    private function applyFailure(string $time): void
    {
        $this->applyChanges(
            new Dn(self::DN),
            OperationalChanges::of(Change::replace(
                PasswordPolicyOid::NAME_PWD_FAILURE_TIME,
                $time,
            )),
        );
    }

    private function applyChanges(
        Dn $dn,
        OperationalChanges $changes,
    ): void {
        $this->subject->atomicMutate(
            $dn,
            static fn(): OperationalChanges => $changes,
        );
    }
}
