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

namespace Tests\Unit\FreeDSx\Ldap\Sync\Convergence;

use FreeDSx\Ldap\Control\Sync\SyncDoneControl;
use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncIdSet;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncNewCookie;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncRefreshDelete;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncRefreshPresent;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Sync\Consumer\ReplicaConsumer;
use FreeDSx\Ldap\Sync\Session;
use Generator;
use PHPUnit\Framework\Constraint\Callback;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Sync\Convergence\ConvergenceProvider;
use Tests\Support\FreeDSx\Ldap\Sync\Convergence\SyncLoopback;

use function array_shift;

final class SyncLoopbackTest extends TestCase
{
    private const UUID = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10";

    private ReplicaConsumer&MockObject $consumer;

    /**
     * @var list<?string>
     */
    private array $opened = [];

    /**
     * @var list<string>
     */
    private array $calls = [];

    protected function setUp(): void
    {
        $this->consumer = $this->createMock(ReplicaConsumer::class);
        $this->consumer
            ->method('persistCookie')
            ->willReturnCallback(function (?string $cookie): void {
                $this->calls[] = 'cookie ' . $cookie;
            });
        $this->consumer
            ->method('applyIdSet')
            ->willReturnCallback(function (): void {
                $this->calls[] = 'idSet';
            });
        $this->consumer
            ->method('startRefresh')
            ->willReturnCallback(function (?string $cookie): void {
                $this->calls[] = 'start ' . ($cookie ?? 'none');
            });
    }

    public function test_a_sync_without_a_checkpoint_cookie_is_a_full_refresh(): void
    {
        $subject = $this->loopback([new SyncNewCookie('c1')]);

        $subject->drain();

        self::assertTrue($subject->startedWithoutCookie());
        self::assertSame(
            [null],
            $this->opened,
        );
    }

    public function test_a_sync_resumes_from_the_checkpoint_cookie(): void
    {
        $this->consumer
            ->method('startingCookie')
            ->willReturn('c0');
        $subject = $this->loopback([new SyncNewCookie('c1')]);

        $subject->drain();

        self::assertFalse($subject->startedWithoutCookie());
        self::assertSame(
            ['c0'],
            $this->opened,
        );
    }

    public function test_a_refresh_ending_in_a_present_phase_is_reconciled_without_refresh_deletes(): void
    {
        $this->consumer
            ->expects(self::once())
            ->method('reconcileRefresh')
            ->with($this->completedRefresh(false));

        $this->loopback([
            new SyncRefreshPresent(
                true,
                'c1',
            ),
            new SyncNewCookie('c1'),
        ])->drain();
    }

    public function test_a_refresh_ending_in_a_delete_phase_is_reconciled_with_refresh_deletes(): void
    {
        $this->consumer
            ->expects(self::once())
            ->method('reconcileRefresh')
            ->with($this->completedRefresh(true));

        $this->loopback([
            new SyncRefreshDelete(
                true,
                'c1',
            ),
            new SyncNewCookie('c1'),
        ])->drain();
    }

    public function test_an_id_set_cookie_is_persisted_before_the_set_is_applied(): void
    {
        $this->loopback([
            new SyncIdSet(
                [self::UUID],
                false,
                'c1',
            ),
            new SyncNewCookie('c1'),
        ])->drain();

        self::assertSame(
            ['start none', 'cookie c1', 'idSet'],
            $this->calls,
        );
    }

    public function test_a_required_refresh_starts_over_from_the_cookie_it_carries(): void
    {
        $subject = $this->loopback(
            [new LdapMessageResponse(
                1,
                new SearchResultDone(ResultCode::SYNCHRONIZATION_REFRESH_REQUIRED),
                new SyncDoneControl('c3'),
            )],
            [new SyncNewCookie('c4')],
        );

        $subject->drain();

        self::assertSame(
            [null, 'c3'],
            $this->opened,
        );
        self::assertSame(
            ['start none', 'start c3', 'cookie c4'],
            $this->calls,
        );
    }

    public function test_draining_stops_at_the_cookie_that_ends_a_poll(): void
    {
        $subject = $this->loopback([
            new SyncNewCookie('c1'),
            new SyncNewCookie('c2'),
        ]);

        self::assertTrue($subject->drain());
        self::assertSame(
            ['start none', 'cookie c1'],
            $this->calls,
        );

        self::assertTrue($subject->drain());
        self::assertSame(
            ['start none', 'cookie c1', 'cookie c2'],
            $this->calls,
        );
    }

    public function test_draining_with_a_limit_stops_after_that_many_messages(): void
    {
        $subject = $this->loopback([
            new SyncIdSet([self::UUID]),
            new SyncIdSet([self::UUID]),
            new SyncIdSet([self::UUID]),
            new SyncNewCookie('c1'),
        ]);

        self::assertFalse($subject->drain(2));
        self::assertSame(
            ['start none', 'idSet', 'idSet'],
            $this->calls,
        );
    }

    public function test_an_entry_from_the_hidden_subtree_is_reported(): void
    {
        $hidden = 'cn=dana,' . ConvergenceProvider::HIDDEN;

        $subject = $this->loopback([
            new LdapMessageResponse(
                1,
                new SearchResultEntry(Entry::fromArray(
                    $hidden,
                    ['cn' => 'dana'],
                )),
                new SyncStateControl(
                    SyncStateControl::STATE_ADD,
                    self::UUID,
                ),
            ),
            new SyncNewCookie('c1'),
        ]);

        $subject->drain();

        self::assertSame(
            [$hidden],
            $subject->leaks(),
        );
    }

    /**
     * @return Callback<Session>
     */
    private function completedRefresh(bool $deletes): Callback
    {
        return self::callback(
            static fn(Session $session): bool => $session->isRefreshComplete()
                && $session->hasRefreshDeletes() === $deletes,
        );
    }

    /**
     * @param list<LdapMessageResponse|SyncNewCookie|SyncIdSet|SyncRefreshPresent|SyncRefreshDelete> ...$streams
     */
    private function loopback(array ...$streams): SyncLoopback
    {
        return new SyncLoopback(
            function (?string $cookie) use (&$streams): Generator {
                $this->opened[] = $cookie;

                foreach (array_shift($streams) ?? [] as $message) {
                    yield $message instanceof LdapMessageResponse
                        ? $message
                        : new LdapMessageResponse(
                            1,
                            $message,
                        );
                }
            },
            $this->consumer,
        );
    }
}
