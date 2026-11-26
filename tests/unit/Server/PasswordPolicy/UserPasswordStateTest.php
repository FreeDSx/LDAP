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

namespace Tests\Unit\FreeDSx\Ldap\Server\PasswordPolicy;

use DateTimeImmutable;
use DateTimeZone;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\GeneralizedTime;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class UserPasswordStateTest extends TestCase
{
    public function test_from_empty_entry_returns_defaults(): void
    {
        $state = UserPasswordState::fromEntry(Entry::fromArray('uid=alice,dc=example,dc=com'));

        self::assertNull($state->changedAt);
        self::assertNull($state->accountLockedAt);
        self::assertFalse($state->permanentlyLocked);
        self::assertSame(
            [],
            $state->failureTimes,
        );
        self::assertSame(
            [],
            $state->history,
        );
        self::assertSame(
            [],
            $state->graceUseTimes,
        );
        self::assertFalse($state->mustChange);
        self::assertNull($state->policySubentry);
        self::assertFalse($state->isLocked());
    }

    public function test_from_entry_decodes_all_state(): void
    {
        $entry = Entry::fromArray(
            'uid=alice,dc=example,dc=com',
            [
                'pwdChangedTime' => '20250101120000Z',
                'pwdAccountLockedTime' => '20250105080000Z',
                'pwdFailureTime' => ['20250105075800Z', '20250105075900Z', '20250105080000Z'],
                'pwdHistory' => [
                    '20240101000000Z#1.3.6.1.4.1.1466.115.121.1.40#9#{SSHA}old',
                ],
                'pwdGraceUseTime' => ['20250102000000Z'],
                'pwdReset' => 'TRUE',
                'pwdPolicySubentry' => 'cn=default,ou=policies,dc=example,dc=com',
            ],
        );

        $state = UserPasswordState::fromEntry($entry);

        self::assertEquals(
            new DateTimeImmutable(
                '2025-01-01T12:00:00Z',
                new DateTimeZone('UTC'),
            ),
            $state->changedAt,
        );
        self::assertEquals(
            new DateTimeImmutable(
                '2025-01-05T08:00:00Z',
                new DateTimeZone('UTC'),
            ),
            $state->accountLockedAt,
        );
        self::assertFalse($state->permanentlyLocked);
        self::assertTrue($state->isLocked());
        self::assertCount(
            3,
            $state->failureTimes,
        );
        self::assertCount(
            1,
            $state->history,
        );
        self::assertSame(
            '{SSHA}old',
            $state->history[0]->data,
        );
        self::assertCount(
            1,
            $state->graceUseTimes,
        );
        self::assertTrue($state->mustChange);
        self::assertSame(
            'cn=default,ou=policies,dc=example,dc=com',
            $state->policySubentry?->toString(),
        );
    }

    public function test_its_attribute_list_holds_everything_a_state_is_read_from(): void
    {
        $entry = Entry::fromArray(
            'uid=alice,dc=example,dc=com',
            [
                'cn' => 'alice',
                'pwdChangedTime' => '20250101120000.250000Z',
                'pwdAccountLockedTime' => '20250105080000Z',
                'pwdFailureTime' => ['20250105075800Z'],
                'pwdHistory' => ['20240101000000Z#1.3.6.1.4.1.1466.115.121.1.40#9#{SSHA}old'],
                'pwdGraceUseTime' => ['20250102000000Z'],
                'pwdReset' => 'TRUE',
                'pwdPolicySubentry' => 'cn=default,ou=policies,dc=example,dc=com',
                'pwdStartTime' => '20240101000000Z',
                'pwdEndTime' => '20300101000000Z',
                'pwdLastSuccess' => '20250104000000Z',
            ],
        );
        $projected = new Entry(
            $entry->getDn(),
            ...array_values(array_filter(
                $entry->getAttributes(),
                static fn(Attribute $attribute): bool => in_array(
                    $attribute->getName(),
                    UserPasswordState::ATTRIBUTES,
                    true,
                ),
            )),
        );

        self::assertEquals(
            UserPasswordState::fromEntry($entry),
            UserPasswordState::fromEntry($projected),
        );
    }

    public function test_permanent_lock_sentinel_is_recognized(): void
    {
        $entry = Entry::fromArray(
            'uid=alice,dc=example,dc=com',
            ['pwdAccountLockedTime' => PasswordPolicyOid::PERMANENT_LOCK_SENTINEL],
        );

        $state = UserPasswordState::fromEntry($entry);

        self::assertTrue($state->permanentlyLocked);
        self::assertTrue($state->isLocked());
        self::assertNull($state->accountLockedAt);
    }

    public function test_failure_count_since_filters_old_entries(): void
    {
        $entry = Entry::fromArray(
            'uid=alice,dc=example,dc=com',
            [
                'pwdFailureTime' => [
                    '20250101000000Z',
                    '20250105000000Z',
                    '20250110000000Z',
                ],
            ],
        );

        $state = UserPasswordState::fromEntry($entry);

        $threshold = new DateTimeImmutable(
            '2025-01-04T00:00:00Z',
            new DateTimeZone('UTC'),
        );

        self::assertSame(
            2,
            $state->failureCountSince($threshold),
        );
    }

    public function test_from_entry_rejects_invalid_generalized_time(): void
    {
        $entry = Entry::fromArray(
            'uid=alice,dc=example,dc=com',
            ['pwdChangedTime' => 'not-a-time'],
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OTHER);

        UserPasswordState::fromEntry($entry);
    }

    public function test_from_entry_rejects_invalid_boolean(): void
    {
        $entry = Entry::fromArray(
            'uid=alice,dc=example,dc=com',
            ['pwdReset' => 'maybe'],
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OTHER);

        UserPasswordState::fromEntry($entry);
    }

    public function test_from_entry_accepts_non_canonical_generalized_time(): void
    {
        $entry = Entry::fromArray(
            'uid=alice,dc=example,dc=com',
            ['pwdChangedTime' => '20250101120000+0530'],
        );

        $state = UserPasswordState::fromEntry($entry);

        self::assertSame(
            '2025-01-01T06:30:00+00:00',
            $state->changedAt?->format('c'),
        );
    }

    public function test_is_superseded_by_an_authoritative_lock(): void
    {
        $local = new UserPasswordState(failureTimes: [$this->at('20250105080000Z')]);

        self::assertTrue($local->isSupersededBy(new UserPasswordState(accountLockedAt: $this->at('20250105080100Z'))));
    }

    public function test_local_lock_is_superseded_by_a_password_change(): void
    {
        $local = new UserPasswordState(
            changedAt: $this->at('20250101120000Z'),
            accountLockedAt: $this->at('20250105080000Z'),
            failureTimes: [$this->at('20250105080000Z')],
        );

        self::assertTrue($local->isSupersededBy(new UserPasswordState(changedAt: $this->at('20250105090000Z'))));
    }

    public function test_local_lock_is_superseded_by_a_reset_stamped_earlier_in_the_failures_second(): void
    {
        $local = new UserPasswordState(
            changedAt: $this->at('20250101120000Z'),
            accountLockedAt: $this->at('20250105080000Z'),
            failureTimes: [$this->at('20250105080000.500000Z')],
        );

        self::assertTrue($local->isSupersededBy(new UserPasswordState(changedAt: $this->at('20250105080000.100000Z'))));
    }

    public function test_local_lock_is_superseded_by_a_newer_success(): void
    {
        $local = new UserPasswordState(
            accountLockedAt: $this->at('20250105080000Z'),
            failureTimes: [$this->at('20250105080000Z')],
        );

        self::assertTrue($local->isSupersededBy(new UserPasswordState(lastSuccess: $this->at('20250105090000Z'))));
    }

    public function test_local_lock_is_kept_while_the_entry_holds_the_same_password(): void
    {
        $local = new UserPasswordState(
            changedAt: $this->at('20250101120000Z'),
            accountLockedAt: $this->at('20250105080000Z'),
            failureTimes: [$this->at('20250105080000Z')],
        );

        self::assertFalse($local->isSupersededBy(new UserPasswordState(changedAt: $this->at('20250101120000Z'))));
    }

    /**
     * @return iterable<string, array{?string, ?string, bool}>
     */
    public static function versionProvider(): iterable
    {
        yield 'the same instant' => [
            '20250105080000.250000Z',
            '20250105080000.250000Z',
            true,
        ];
        yield 'whole seconds against a zero fraction' => [
            '20250105080000Z',
            '20250105080000.000000Z',
            true,
        ];
        yield 'a microsecond apart' => [
            '20250105080000.250000Z',
            '20250105080000.250001Z',
            false,
        ];
        yield 'both absent' => [
            null,
            null,
            true,
        ];
        yield 'one absent' => [
            '20250105080000Z',
            null,
            false,
        ];
    }

    #[DataProvider('versionProvider')]
    public function test_two_password_versions_are_the_same_only_at_the_same_instant(
        ?string $version,
        ?string $other,
        bool $same,
    ): void {
        self::assertSame(
            $same,
            UserPasswordState::isSameVersion(
                $version === null ? null : $this->at($version),
                $other === null ? null : $this->at($other),
            ),
        );
    }

    public function test_sub_threshold_failures_are_kept_until_reset(): void
    {
        $local = new UserPasswordState(failureTimes: [$this->at('20250105080000Z')]);

        self::assertFalse($local->isSupersededBy(new UserPasswordState()));
    }

    public function test_sub_threshold_failures_are_superseded_by_a_newer_success(): void
    {
        $local = new UserPasswordState(failureTimes: [$this->at('20250105080000Z')]);

        self::assertTrue($local->isSupersededBy(new UserPasswordState(lastSuccess: $this->at('20250105080100Z'))));
    }

    public function test_a_success_predating_the_failure_does_not_supersede(): void
    {
        $local = new UserPasswordState(failureTimes: [$this->at('20250105080000Z')]);

        self::assertFalse($local->isSupersededBy(new UserPasswordState(lastSuccess: $this->at('20250105075900Z'))));
    }

    public function test_empty_local_state_is_always_superseded(): void
    {
        self::assertTrue((new UserPasswordState())->isSupersededBy(new UserPasswordState()));
    }

    private function at(string $generalizedTime): DateTimeImmutable
    {
        return GeneralizedTime::parse($generalizedTime);
    }
}
