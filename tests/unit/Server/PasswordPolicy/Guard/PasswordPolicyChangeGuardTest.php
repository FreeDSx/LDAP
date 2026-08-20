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

namespace Tests\Unit\FreeDSx\Ldap\Server\PasswordPolicy\Guard;

use DateInterval;
use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\GeneralizedTime;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Clock\ClockInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Attempt\PasswordModifyAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\PasswordPolicyChangeGuard;
use FreeDSx\Ldap\Server\PasswordPolicy\HistoryEntry;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordChangeRules;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordQualityRules;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use PHPUnit\Framework\TestCase;
use FreeDSx\Ldap\ServerOptions;
use Tests\Support\FreeDSx\Ldap\Clock\FrozenClock;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;

final class PasswordPolicyChangeGuardTest extends TestCase
{
    use ServerContainerTrait;

    private const NOW = '2026-05-20T12:00:00Z';

    private const DN = 'cn=user,dc=foo,dc=bar';

    private FrozenClock $clock;

    private PasswordPolicyContext $context;

    private RecordingLogger $logger;

    protected function setUp(): void
    {
        $this->clock = FrozenClock::fromString(self::NOW);
        $this->context = new PasswordPolicyContext();
        $this->logger = new RecordingLogger();
    }

    public function test_no_governing_policy_yields_no_changes(): void
    {
        $changes = $this->guard(null)->enforce(
            $this->attempt($this->entry(), 'whatever'),
        );

        self::assertTrue($changes->isEmpty());
        self::assertNull($this->context->getOutcome());
    }

    public function test_too_short_password_is_rejected(): void
    {
        $this->assertRejectedWith(
            PwdPolicyError::PASSWORD_TOO_SHORT,
            ResultCode::CONSTRAINT_VIOLATION,
            fn(): mixed => $this->guard(new PasswordPolicy(
                quality: new PasswordQualityRules(minLength: 8),
            ))->enforce($this->attempt($this->entry(), 'short')),
        );
    }

    public function test_change_within_min_age_is_rejected(): void
    {
        $this->assertRejectedWith(
            PwdPolicyError::PASSWORD_TOO_YOUNG,
            ResultCode::CONSTRAINT_VIOLATION,
            fn(): mixed => $this->guard(new PasswordPolicy(
                change: new PasswordChangeRules(minAge: 3600),
            ))->enforce($this->attempt(
                $this->entry([
                    PasswordPolicyOid::NAME_PWD_CHANGED_TIME => $this->minutesAgo(30),
                ]),
                'a-fresh-password',
            )),
        );
    }

    public function test_reused_password_is_rejected(): void
    {
        $this->assertRejectedWith(
            PwdPolicyError::PASSWORD_IN_HISTORY,
            ResultCode::CONSTRAINT_VIOLATION,
            fn(): mixed => $this->guard(new PasswordPolicy(
                quality: new PasswordQualityRules(inHistory: 5),
            ))->enforce($this->attempt(
                $this->entry([
                    PasswordPolicyOid::NAME_PWD_HISTORY => $this->historyValue('reused-password'),
                ]),
                'reused-password',
            )),
        );
    }

    public function test_safe_modify_requires_the_old_password(): void
    {
        $this->assertRejectedWith(
            PwdPolicyError::MUST_SUPPLY_OLD_PASSWORD,
            ResultCode::CONSTRAINT_VIOLATION,
            fn(): mixed => $this->guard(new PasswordPolicy(
                change: new PasswordChangeRules(safeModify: true),
            ))->enforce($this->attempt($this->entry(), 'a-fresh-password')),
        );
    }

    public function test_self_change_blocked_when_not_allowed(): void
    {
        $this->assertRejectedWith(
            PwdPolicyError::PASSWORD_MOD_NOT_ALLOWED,
            ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            fn(): mixed => $this->guard(new PasswordPolicy(
                change: new PasswordChangeRules(allowUserChange: false),
            ))->enforce($this->attempt($this->entry(), 'a-fresh-password')),
        );
    }

    public function test_allowed_change_returns_bookkeeping_deltas(): void
    {
        $changes = $this->guard(new PasswordPolicy(
            quality: new PasswordQualityRules(inHistory: 3),
        ))->enforce($this->attempt(
            $this->entry([PasswordPolicyOid::NAME_PWD_RESET => 'TRUE']),
            'a-fresh-password',
            '{BCRYPT}' . password_hash('a-fresh-password', PASSWORD_BCRYPT, ['cost' => 4]),
        ));

        self::assertNull($this->context->getOutcome());
        $names = $this->changedAttributes($changes->changes);
        self::assertContains(
            PasswordPolicyOid::NAME_PWD_CHANGED_TIME,
            $names,
        );
        self::assertContains(
            PasswordPolicyOid::NAME_PWD_HISTORY,
            $names,
        );
        self::assertContains(
            PasswordPolicyOid::NAME_PWD_RESET,
            $names,
        );
    }

    public function test_admin_reset_is_exempt_from_safe_modify_and_min_age(): void
    {
        $changes = $this->guard(new PasswordPolicy(
            change: new PasswordChangeRules(
                minAge: 3600,
                safeModify: true,
            ),
        ))->enforce($this->attempt(
            $this->entry([
                PasswordPolicyOid::NAME_PWD_CHANGED_TIME => $this->minutesAgo(30),
            ]),
            'admin-set-password',
            isSelf: false,
        ));

        self::assertNull($this->context->getOutcome());
        self::assertContains(
            PasswordPolicyOid::NAME_PWD_CHANGED_TIME,
            $this->changedAttributes($changes->changes),
        );
    }

    protected function makeServerOptions(): ServerOptions
    {
        return TestServerOptions::cheaplyHashed();
    }

    private function assertRejectedWith(
        int $expectedError,
        int $expectedResultCode,
        callable $act,
    ): void {
        try {
            $act();
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                $expectedResultCode,
                $e->getCode(),
            );
        }

        self::assertSame(
            $expectedError,
            $this->context->getOutcome()?->errorCode,
        );
        self::assertContains(
            ServerEvent::PasswordPolicyChangeRejected->value,
            $this->recordedEvents(),
        );
    }

    private function attempt(
        Entry $target,
        string $newPassword,
        string $hashedNewPassword = '{BCRYPT}hash',
        ?string $oldPassword = null,
        bool $isSelf = true,
    ): PasswordModifyAttempt {
        return new PasswordModifyAttempt(
            target: $target,
            newPassword: $newPassword,
            hashedNewPassword: $hashedNewPassword,
            oldPassword: $oldPassword,
            isSelf: $isSelf,
        );
    }

    private function guard(?PasswordPolicy $policy): PasswordPolicyChangeGuard
    {
        return new PasswordPolicyChangeGuard(
            $this->fromContainer(
                PasswordPolicyEngine::class,
                [ClockInterface::class => $this->clock],
            ),
            new PasswordPolicyResolver(
                $this->createMock(LdapBackendInterface::class),
                null,
                $policy,
            ),
            $this->context,
            new EventLogger(
                $this->logger,
                EventLogPolicy::all(),
            ),
        );
    }

    /**
     * @param array<string, string> $extra
     */
    private function entry(array $extra = []): Entry
    {
        return Entry::fromArray(
            self::DN,
            [
                'objectClass' => ['inetOrgPerson'],
                'cn' => ['user'],
            ] + $extra,
        );
    }

    private function minutesAgo(int $minutes): string
    {
        return GeneralizedTime::format(
            $this->clock
                ->now()
                ->sub(new DateInterval(sprintf('PT%dM', $minutes))),
        );
    }

    private function historyValue(string $plaintext): string
    {
        return HistoryEntry::forStoredPassword(
            $this->clock->now(),
            '{BCRYPT}' . password_hash($plaintext, PASSWORD_BCRYPT, ['cost' => 4]),
        )->encode();
    }

    /**
     * @param list<\FreeDSx\Ldap\Entry\Change> $changes
     * @return list<string>
     */
    private function changedAttributes(array $changes): array
    {
        return array_map(
            static fn(\FreeDSx\Ldap\Entry\Change $change): string => $change->getAttribute()->getName(),
            $changes,
        );
    }

    /**
     * @return list<string>
     */
    private function recordedEvents(): array
    {
        $events = [];
        foreach ($this->logger->records as $record) {
            $event = $record['context']['event'] ?? null;
            if (is_string($event)) {
                $events[] = $event;
            }
        }

        return $events;
    }
}
