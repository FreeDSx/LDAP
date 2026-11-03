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

namespace Tests\Unit\FreeDSx\Ldap\Server\PasswordPolicy\Constraint;

use DateTimeImmutable;
use DateTimeZone;
use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\HistoryConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\HistoryEntry;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordQualityRules;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;
use PHPUnit\Framework\TestCase;

use function microtime;
use function min;
use function str_repeat;

final class HistoryConstraintTest extends TestCase
{
    /**
     * Timings are taken as a best-of, since scheduling noise can only ever add to a measurement.
     */
    private const TIMING_SAMPLES = 5;

    /**
     * A skipped comparison lands near zero rather than near parity, which leaves scheduling noise far below the bar.
     */
    private const MAX_SKIPPED_COST_RATIO = 0.1;

    private HistoryConstraint $subject;

    protected function setUp(): void
    {
        $this->subject = new HistoryConstraint(new PasswordHashService(hashCost: 4));
    }

    public function test_zero_depth_skips(): void
    {
        self::assertNull(
            $this->subject->check(
                $this->attempt(
                    inHistory: 0,
                    historyPlaintexts: ['secret'],
                ),
            ),
        );
    }

    public function test_null_depth_skips(): void
    {
        self::assertNull(
            $this->subject->check(
                $this->attempt(
                    inHistory: null,
                    historyPlaintexts: ['secret'],
                ),
            ),
        );
    }

    public function test_empty_history_skips(): void
    {
        self::assertNull(
            $this->subject->check(
                $this->attempt(
                    inHistory: 5,
                    historyPlaintexts: [],
                ),
            ),
        );
    }

    public function test_new_password_not_in_history_passes(): void
    {
        self::assertNull(
            $this->subject->check(
                $this->attempt(
                    inHistory: 5,
                    historyPlaintexts: ['old1', 'old2'],
                    newPassword: 'completely-different',
                ),
            ),
        );
    }

    public function test_new_password_matching_first_entry_denies(): void
    {
        $outcome = $this->subject->check(
            $this->attempt(
                inHistory: 5,
                historyPlaintexts: ['target', 'other'],
                newPassword: 'target',
            ),
        );

        self::assertNotNull($outcome);
        self::assertTrue($outcome->denied);
        self::assertSame(
            PwdPolicyError::PASSWORD_IN_HISTORY,
            $outcome->errorCode,
        );
    }

    public function test_new_password_matching_later_entry_denies(): void
    {
        $outcome = $this->subject->check(
            $this->attempt(
                inHistory: 5,
                historyPlaintexts: ['other', 'target'],
                newPassword: 'target',
            ),
        );

        self::assertNotNull($outcome);
        self::assertTrue($outcome->denied);
    }

    public function test_a_new_password_over_the_length_limit_is_checked_without_hashing(): void
    {
        $history = [
            'old1',
            'old2',
            'old3',
        ];

        $compared = $this->timeCheck($this->attempt(
            inHistory: 5,
            historyPlaintexts: $history,
            newPassword: 'completely-different',
        ));
        $overLength = $this->timeCheck($this->attempt(
            inHistory: 5,
            historyPlaintexts: $history,
            newPassword: str_repeat(
                'a',
                513,
            ),
        ));

        self::assertLessThan(
            $compared * self::MAX_SKIPPED_COST_RATIO,
            $overLength,
        );
    }

    /**
     * Fastest of several checks of one attempt, in seconds.
     */
    private function timeCheck(PasswordChangeAttempt $attempt): float
    {
        $fastest = null;

        for ($sample = 0; $sample < self::TIMING_SAMPLES; $sample++) {
            $start = microtime(true);
            $this->subject->check($attempt);
            $elapsed = microtime(true) - $start;
            $fastest = $fastest === null
                ? $elapsed
                : min(
                    $fastest,
                    $elapsed,
                );
        }

        return (float) $fastest;
    }

    /**
     * @param int<0, max>|null $inHistory
     * @param list<string> $historyPlaintexts
     */
    private function attempt(
        ?int $inHistory,
        array $historyPlaintexts,
        string $newPassword = 'newpw',
    ): PasswordChangeAttempt {
        $history = array_values(array_map(
            fn(string $plain): HistoryEntry => HistoryEntry::forStoredPassword(
                new DateTimeImmutable(
                    '2026-05-15T00:00:00Z',
                    new DateTimeZone('UTC'),
                ),
                '{BCRYPT}' . password_hash($plain, PASSWORD_BCRYPT, ['cost' => 4]),
            ),
            $historyPlaintexts,
        ));

        return new PasswordChangeAttempt(
            newPassword: $newPassword,
            oldPassword: null,
            state: new UserPasswordState(history: $history),
            policy: new PasswordPolicy(
                quality: new PasswordQualityRules(inHistory: $inHistory),
            ),
            isSelf: true,
        );
    }
}
