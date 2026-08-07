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

namespace FreeDSx\Ldap\Server\PasswordPolicy;

use DateTimeImmutable;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\PasswordPolicyException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\GeneralizedTime;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;

/**
 * Immutable snapshot of a user entry's draft-behera password-policy operational attributes.
 */
final readonly class UserPasswordState
{
    /**
     * @param list<DateTimeImmutable> $failureTimes
     * @param list<HistoryEntry> $history
     * @param list<DateTimeImmutable> $graceUseTimes
     */
    public function __construct(
        public ?DateTimeImmutable $changedAt = null,
        public ?DateTimeImmutable $accountLockedAt = null,
        public bool $permanentlyLocked = false,
        public array $failureTimes = [],
        public array $history = [],
        public array $graceUseTimes = [],
        public bool $mustChange = false,
        public ?Dn $policySubentry = null,
        public ?DateTimeImmutable $startTime = null,
        public ?DateTimeImmutable $endTime = null,
        public ?DateTimeImmutable $lastSuccess = null,
    ) {}

    /**
     * Unreadable state fails the operation rather than the session, and says nothing about the entry it came from.
     *
     * @throws OperationException when any operational attribute value fails to parse.
     */
    public static function fromEntry(Entry $entry): self
    {
        try {
            return self::parse($entry);
        } catch (PasswordPolicyException $e) {
            throw new OperationException(
                'The password policy state could not be read.',
                ResultCode::OTHER,
                $e,
            );
        }
    }

    public function isLocked(): bool
    {
        return $this->accountLockedAt !== null
            || $this->permanentlyLocked;
    }

    /**
     * True when $authoritative (the primary's replicated entry) supersedes this local volatile state so it can be
     * dropped, which holds when the entry:
     *
     *   - is authoritatively locked, or
     *   - records a success past our newest failure, or
     *   - records a credential change past our newest failure.
     */
    public function isSupersededBy(self $authoritative): bool
    {
        if ($authoritative->isLocked()) {
            return true;
        }

        $newestFailure = $this->newestFailureTime();
        if ($newestFailure === null) {
            // No local failures to weigh a reset against
            // Drop only when there is also no local lock left to enforce.
            return !$this->isLocked();
        }

        // A success or credential change past our newest failure means the primary reset the counter and any lock.
        return self::isAfter(
            $authoritative->lastSuccess,
            $newestFailure,
        ) || self::isAfter(
            $authoritative->changedAt,
            $newestFailure,
        );
    }

    /**
     * Count failures recorded at or after $threshold; used to honor pwdFailureCountInterval.
     *
     * @return int<0, max>
     */
    public function failureCountSince(DateTimeImmutable $threshold): int
    {
        $count = 0;

        foreach ($this->failureTimes as $time) {
            if ($time >= $threshold) {
                $count++;
            }
        }

        return $count;
    }

    /**
     * @throws PasswordPolicyException when any operational attribute value fails to parse.
     */
    private static function parse(Entry $entry): self
    {
        return new self(
            changedAt: self::readGeneralizedTime(
                $entry,
                PasswordPolicyOid::NAME_PWD_CHANGED_TIME,
            ),
            accountLockedAt: self::readLockedAt($entry),
            permanentlyLocked: self::isPermanentLockSentinel($entry),
            failureTimes: self::readGeneralizedTimeList(
                $entry,
                PasswordPolicyOid::NAME_PWD_FAILURE_TIME,
            ),
            history: self::readHistory($entry),
            graceUseTimes: self::readGeneralizedTimeList(
                $entry,
                PasswordPolicyOid::NAME_PWD_GRACE_USE_TIME,
            ),
            mustChange: self::readBoolean(
                $entry,
                PasswordPolicyOid::NAME_PWD_RESET,
            ) ?? false,
            policySubentry: self::readDn(
                $entry,
                PasswordPolicyOid::NAME_PWD_POLICY_SUBENTRY,
            ),
            startTime: self::readGeneralizedTime(
                $entry,
                PasswordPolicyOid::NAME_PWD_START_TIME,
            ),
            endTime: self::readGeneralizedTime(
                $entry,
                PasswordPolicyOid::NAME_PWD_END_TIME,
            ),
            lastSuccess: self::readGeneralizedTime(
                $entry,
                PasswordPolicyOid::NAME_PWD_LAST_SUCCESS,
            ),
        );
    }

    private function newestFailureTime(): ?DateTimeImmutable
    {
        $newest = null;

        foreach ($this->failureTimes as $time) {
            if ($newest === null || $time > $newest) {
                $newest = $time;
            }
        }

        return $newest;
    }

    private static function isAfter(
        ?DateTimeImmutable $candidate,
        DateTimeImmutable $threshold,
    ): bool {
        return $candidate !== null
            && $candidate > $threshold;
    }

    private static function readLockedAt(Entry $entry): ?DateTimeImmutable
    {
        $raw = $entry
            ->get(PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME)
            ?->firstValue();
        if ($raw === null || $raw === PasswordPolicyOid::PERMANENT_LOCK_SENTINEL) {
            return null;
        }

        return self::parseGeneralizedTime(
            $raw,
            $entry,
            PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
        );
    }

    private static function isPermanentLockSentinel(Entry $entry): bool
    {
        $raw = $entry
            ->get(PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME)
            ?->firstValue();

        return $raw === PasswordPolicyOid::PERMANENT_LOCK_SENTINEL;
    }

    private static function readGeneralizedTime(
        Entry $entry,
        string $name,
    ): ?DateTimeImmutable {
        $raw = $entry->get($name)?->firstValue();
        if ($raw === null) {
            return null;
        }

        return self::parseGeneralizedTime(
            $raw,
            $entry,
            $name,
        );
    }

    /**
     * @return list<DateTimeImmutable>
     */
    private static function readGeneralizedTimeList(
        Entry $entry,
        string $name,
    ): array {
        $attr = $entry->get($name);
        if (!$attr instanceof Attribute) {
            return [];
        }

        $values = [];
        foreach ($attr->getValues() as $raw) {
            $values[] = self::parseGeneralizedTime(
                $raw,
                $entry,
                $name,
            );
        }

        return $values;
    }

    /**
     * @return list<HistoryEntry>
     */
    private static function readHistory(Entry $entry): array
    {
        $attr = $entry->get(PasswordPolicyOid::NAME_PWD_HISTORY);
        if (!$attr instanceof Attribute) {
            return [];
        }

        $values = [];
        foreach ($attr->getValues() as $raw) {
            $values[] = HistoryEntry::decode($raw);
        }

        return $values;
    }

    private static function readBoolean(
        Entry $entry,
        string $name,
    ): ?bool {
        $raw = $entry->get($name)?->firstValue();
        if ($raw === null) {
            return null;
        }

        return match (strtoupper($raw)) {
            'TRUE' => true,
            'FALSE' => false,
            default => throw new PasswordPolicyException(sprintf(
                'Entry "%s" has non-boolean value "%s" for %s.',
                $entry->getDn()->toString(),
                $raw,
                $name,
            )),
        };
    }

    private static function readDn(
        Entry $entry,
        string $name,
    ): ?Dn {
        $raw = $entry->get($name)?->firstValue();
        if ($raw === null || $raw === '') {
            return null;
        }

        return new Dn($raw);
    }

    /**
     * @throws PasswordPolicyException
     */
    private static function parseGeneralizedTime(
        string $raw,
        Entry $entry,
        string $name,
    ): DateTimeImmutable {
        try {
            return GeneralizedTime::parse($raw);
        } catch (InvalidArgumentException $cause) {
            throw new PasswordPolicyException(
                sprintf(
                    'Entry "%s" has non-GeneralizedTime value "%s" for %s.',
                    $entry->getDn()->toString(),
                    $raw,
                    $name,
                ),
                previous: $cause,
            );
        }
    }
}
