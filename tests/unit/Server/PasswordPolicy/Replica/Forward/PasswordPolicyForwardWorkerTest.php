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

namespace Tests\Unit\FreeDSx\Ldap\Server\PasswordPolicy\Replica\Forward;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\ForwardStateException;
use FreeDSx\Ldap\Exception\ForwardStateRejectedException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operation\Request\ForwardPasswordPolicyStateRequest;
use FreeDSx\Ldap\Schema\Definition\GeneralizedTime;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\Forward\ForwardStateSenderInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\Forward\PasswordPolicyForwardWorker;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;
use FreeDSx\Ldap\ServerOptions;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class PasswordPolicyForwardWorkerTest extends TestCase
{
    use ServerContainerTrait;

    private const DN = 'cn=foo,dc=example,dc=com';

    private ReplicaPasswordStateStoreInterface $store;

    private ForwardStateSenderInterface&MockObject $sender;

    /**
     * @var list<ForwardPasswordPolicyStateRequest>
     */
    private array $sent;

    /**
     * @var list<float>
     */
    private array $slept;

    private PasswordPolicyForwardWorker $subject;

    protected function setUp(): void
    {
        // Both resolve from the memoised container, so the state store shares the storage holding the subjects.
        $storage = $this->fromContainer(EntryStorageInterface::class);
        foreach ([self::DN, 'cn=a,dc=example,dc=com', 'cn=b,dc=example,dc=com'] as $subject) {
            $dn = new Dn($subject);
            $storage->store(new Entry(
                $dn,
                new Attribute('cn', $dn->getRdn()->getValue()),
            ));
        }

        $this->store = $this->fromContainer(ReplicaPasswordStateStoreInterface::class);
        $this->sent = [];
        $this->slept = [];
        $this->sender = $this->createMock(ForwardStateSenderInterface::class);

        // Stop after each sleep so run() executes exactly one drain iteration per test.
        $sleeper = $this->createMock(SleeperInterface::class);
        $sleeper->method('sleep')
            ->willReturnCallback(function (float $seconds): void {
                $this->slept[] = $seconds;
                $this->subject->stop();
            });

        $this->subject = new PasswordPolicyForwardWorker(
            $this->store,
            $this->sender,
            $sleeper,
        );
    }

    public function test_it_forwards_pending_state_and_advances_the_watermark(): void
    {
        $this->recordSends();
        $this->seedFailure('20260520120000Z');

        $forwarded = $this->subject->forwardOnce();

        self::assertSame(
            1,
            $forwarded,
        );
        self::assertCount(
            1,
            $this->sent,
        );
        self::assertSame(
            self::DN,
            $this->sent[0]->getDn()->toString(),
        );
        self::assertSame(
            ['20260520120000Z'],
            array_map(
                static fn($time): string => GeneralizedTime::format($time),
                $this->sent[0]->getFailureTimes(),
            ),
        );
        self::assertSame(
            [],
            $this->store->listUnforwarded(),
        );
    }

    public function test_it_drains_every_pending_subject(): void
    {
        $this->recordSends();
        $this->seedFailure('20260520120000Z', 'cn=a,dc=example,dc=com');
        $this->seedFailure('20260520120000Z', 'cn=b,dc=example,dc=com');

        self::assertSame(
            2,
            $this->subject->forwardOnce(),
        );
        self::assertSame(
            [],
            $this->store->listUnforwarded(),
        );
    }

    public function test_a_send_failure_leaves_the_subject_pending(): void
    {
        $this->sender
            ->method('send')
            ->willThrowException(new ForwardStateException('primary is unreachable'));
        $this->seedFailure('20260520120000Z');

        $this->expectException(ForwardStateException::class);

        try {
            $this->subject->forwardOnce();
        } finally {
            self::assertCount(
                1,
                $this->store->listUnforwarded(),
            );
        }
    }

    public function test_a_subject_the_primary_refuses_does_not_hold_back_the_others(): void
    {
        $this->sender
            ->method('send')
            ->willReturnCallback(function (ForwardPasswordPolicyStateRequest $request): void {
                if ($request->getDn()->toString() === 'cn=a,dc=example,dc=com') {
                    throw new ForwardStateRejectedException('Access denied.', ResultCode::INSUFFICIENT_ACCESS_RIGHTS);
                }

                $this->sent[] = $request;
            });
        $this->seedFailure('20260520120000Z', 'cn=a,dc=example,dc=com');
        $this->seedFailure('20260520120000Z', 'cn=b,dc=example,dc=com');

        $forwarded = $this->subject->forwardOnce();

        self::assertSame(
            1,
            $forwarded,
        );
        self::assertSame(
            ['cn=b,dc=example,dc=com'],
            array_map(
                static fn(ForwardPasswordPolicyStateRequest $request): string => $request->getDn()->toString(),
                $this->sent,
            ),
        );
        self::assertSame(
            ['cn=a,dc=example,dc=com'],
            array_map(
                static fn($pending): string => $pending->dn->toString(),
                $this->store->listUnforwarded(),
            ),
        );
    }

    public function test_a_refused_subject_is_retried_on_a_widening_gap_rather_than_every_drain(): void
    {
        $attempts = 0;
        $this->sender
            ->method('send')
            ->willReturnCallback(static function () use (&$attempts): void {
                $attempts++;

                throw new ForwardStateRejectedException('Access denied.', ResultCode::INSUFFICIENT_ACCESS_RIGHTS);
            });
        $this->seedFailure('20260520120000Z');

        for ($drain = 1; $drain <= 8; $drain++) {
            $this->subject->forwardOnce();
        }

        // Attempted on drains 1, 2, 4 and 8 only.
        self::assertSame(
            4,
            $attempts,
        );
        self::assertCount(
            1,
            $this->store->listUnforwarded(),
        );
    }

    public function test_a_refused_subject_is_attempted_again_as_soon_as_its_state_changes(): void
    {
        $attempts = 0;
        $this->sender
            ->method('send')
            ->willReturnCallback(static function () use (&$attempts): void {
                $attempts++;

                throw new ForwardStateRejectedException('Access denied.', ResultCode::INSUFFICIENT_ACCESS_RIGHTS);
            });
        $this->seedFailure('20260520120000Z');

        $this->subject->forwardOnce();
        $this->subject->forwardOnce();
        $this->subject->forwardOnce();
        // A new observation moves the subject on, so the widening gap no longer applies to it.
        $this->seedFailure('20260520120500Z');
        $this->subject->forwardOnce();

        self::assertSame(
            3,
            $attempts,
        );
    }

    public function test_run_drains_then_sleeps_the_poll_interval(): void
    {
        $this->recordSends();
        $this->seedFailure('20260520120000Z');

        $this->subject->run();

        self::assertCount(
            1,
            $this->sent,
        );
        self::assertSame(
            [PasswordPolicyForwardWorker::DEFAULT_INTERVAL_SECONDS],
            $this->slept,
        );
        self::assertSame(
            [],
            $this->store->listUnforwarded(),
        );
    }

    public function test_run_backs_off_and_leaves_state_pending_on_a_delivery_failure(): void
    {
        $this->sender
            ->method('send')
            ->willThrowException(new ForwardStateException('primary is unreachable'));
        $this->seedFailure('20260520120000Z');

        $this->subject->run();

        self::assertSame(
            [1.0],
            $this->slept,
        );
        self::assertCount(
            1,
            $this->store->listUnforwarded(),
        );
    }

    protected function makeServerOptions(): ServerOptions
    {
        return TestServerOptions::sqlite();
    }

    private function recordSends(): void
    {
        $this->sender
            ->method('send')
            ->willReturnCallback(function (ForwardPasswordPolicyStateRequest $request): void {
                $this->sent[] = $request;
            });
    }

    private function seedFailure(
        string $time,
        string $dn = self::DN,
    ): void {
        $this->store->atomicMutate(
            new Dn($dn),
            static fn(): OperationalChanges => OperationalChanges::of(Change::replace(
                PasswordPolicyOid::NAME_PWD_FAILURE_TIME,
                $time,
            )),
        );
    }
}
