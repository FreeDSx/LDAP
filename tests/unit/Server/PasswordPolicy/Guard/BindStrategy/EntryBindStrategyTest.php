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

namespace Tests\Unit\FreeDSx\Ldap\Server\PasswordPolicy\Guard\BindStrategy;

use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Write\Command\ComputeUpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\PasswordPolicy\Attempt\PasswordBindAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeConstraintChain;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\PasswordPolicyOutcome;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\RecordedOutcome;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\BindStrategy\EntryBindStrategy;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Clock\FrozenClock;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;

final class EntryBindStrategyTest extends TestCase
{
    private const DN = 'cn=foo,dc=example,dc=com';

    private WriteHandlerInterface&MockObject $writes;

    private RecordingLogger $logger;

    private EntryBindStrategy $subject;

    protected function setUp(): void
    {
        $this->writes = $this->createMock(WriteHandlerInterface::class);
        $this->logger = new RecordingLogger();
        $this->subject = new EntryBindStrategy(
            new PasswordPolicyEngine(
                clock: FrozenClock::fromString('2026-05-20T12:00:00Z'),
                changeConstraints: new PasswordChangeConstraintChain([]),
            ),
            $this->writes,
            new EventLogger(
                $this->logger,
                EventLogPolicy::all(),
            ),
        );
    }

    public function test_a_refused_write_keeps_the_decision_already_made(): void
    {
        $locked = new RecordedOutcome(
            PasswordPolicyOutcome::deny(
                PwdPolicyError::ACCOUNT_LOCKED,
                ResultCode::INVALID_CREDENTIALS,
                'The account is locked.',
            ),
            OperationalChanges::none(),
        );
        $this->refuseWritesAfterDeciding();

        self::assertSame(
            $locked,
            $this->subject->record(
                $this->attempt(),
                fn(UserPasswordState $state): RecordedOutcome => $locked,
            ),
        );
    }

    public function test_a_refused_write_is_logged_naming_the_entry_and_the_refusal(): void
    {
        $this->refuseWritesAfterDeciding();

        $this->subject->record(
            $this->attempt(),
            fn(UserPasswordState $state): RecordedOutcome => $this->allowed(),
        );

        $context = $this->logger->records[0]['context'] ?? [];
        self::assertSame(
            [
                ServerEvent::PasswordPolicyStateNotRecorded->value,
                ResultCode::ADMIN_LIMIT_EXCEEDED,
                [EventContext::DN => self::DN],
            ],
            [
                $context[EventContext::EVENT] ?? null,
                $context[EventContext::RESULT_CODE] ?? null,
                $context[EventContext::TARGET] ?? null,
            ],
        );
    }

    public function test_a_written_state_logs_nothing(): void
    {
        $this->writes
            ->method('handle')
            ->willReturnCallback(function (ComputeUpdateCommand $command): void {
                ($command->compute)(new Entry(new Dn(self::DN)));
            });

        $this->subject->record(
            $this->attempt(),
            fn(UserPasswordState $state): RecordedOutcome => $this->allowed(),
        );

        self::assertSame(
            [],
            $this->logger->records,
        );
    }

    private function refuseWritesAfterDeciding(): void
    {
        $this->writes
            ->method('handle')
            ->willReturnCallback(function (ComputeUpdateCommand $command): void {
                ($command->compute)(new Entry(new Dn(self::DN)));

                throw new OperationException(
                    'Attribute "userPassword" holds 2 values, which is beyond the limit of 1.',
                    ResultCode::ADMIN_LIMIT_EXCEEDED,
                );
            });
    }

    private function allowed(): RecordedOutcome
    {
        return new RecordedOutcome(
            PasswordPolicyOutcome::allow(),
            OperationalChanges::none(),
        );
    }

    private function attempt(): PasswordBindAttempt
    {
        return new PasswordBindAttempt(
            'foo',
            new Dn(self::DN),
            '6c5d4e3f-2a1b-4c0d-9e8f-7a6b5c4d3e2f',
            new UserPasswordState(),
            new PasswordPolicy(),
        );
    }
}
