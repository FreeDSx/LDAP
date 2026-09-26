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

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\PasswordPolicyException;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordChangeRules;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordExpirationRules;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordLockoutRules;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordQualityRules;

/**
 * Decoded view of a pwdPolicy entry per draft-behera-ldap-password-policy-10 §5.2.
 *
 * Nullable fields on the rule DTOs mean "policy unspecified" and are interpreted as "no limit" by the engine.
 *
 * @api
 */
final readonly class PasswordPolicy
{
    public function __construct(
        public string $pwdAttribute = AttributeTypeOid::NAME_USER_PASSWORD,
        public PasswordQualityRules $quality = new PasswordQualityRules(),
        public PasswordChangeRules $change = new PasswordChangeRules(),
        public PasswordExpirationRules $expiration = new PasswordExpirationRules(),
        public PasswordLockoutRules $lockout = new PasswordLockoutRules(),
    ) {}

    /**
     * @throws PasswordPolicyException when pwdAttribute is missing or any value fails to parse.
     */
    public static function fromEntry(Entry $entry): self
    {
        $pwdAttribute = $entry
            ->get(PasswordPolicyOid::NAME_PWD_ATTRIBUTE)
            ?->firstValue();
        if ($pwdAttribute === null || $pwdAttribute === '') {
            throw new PasswordPolicyException(sprintf(
                'pwdPolicy entry "%s" is missing the required pwdAttribute.',
                $entry->getDn()->toString(),
            ));
        }

        return new self(
            $pwdAttribute,
            quality: self::readQuality($entry),
            change: self::readChange($entry),
            expiration: self::readExpiration($entry),
            lockout: self::readLockout($entry),
        );
    }

    private static function readQuality(Entry $entry): PasswordQualityRules
    {
        return new PasswordQualityRules(
            minLength: self::readInt(
                $entry,
                PasswordPolicyOid::NAME_PWD_MIN_LENGTH,
            ),
            maxLength: self::readInt(
                $entry,
                PasswordPolicyOid::NAME_PWD_MAX_LENGTH,
            ),
            inHistory: self::readInt(
                $entry,
                PasswordPolicyOid::NAME_PWD_IN_HISTORY,
            ),
            checkQuality: self::readInt(
                $entry,
                PasswordPolicyOid::NAME_PWD_CHECK_QUALITY,
            ),
        );
    }

    private static function readChange(Entry $entry): PasswordChangeRules
    {
        return new PasswordChangeRules(
            minAge: self::readInt(
                $entry,
                PasswordPolicyOid::NAME_PWD_MIN_AGE,
            ),
            mustChange: self::readBool(
                $entry,
                PasswordPolicyOid::NAME_PWD_MUST_CHANGE,
            ),
            allowUserChange: self::readBool(
                $entry,
                PasswordPolicyOid::NAME_PWD_ALLOW_USER_CHANGE,
            ),
            safeModify: self::readBool(
                $entry,
                PasswordPolicyOid::NAME_PWD_SAFE_MODIFY,
            ),
        );
    }

    private static function readExpiration(Entry $entry): PasswordExpirationRules
    {
        return new PasswordExpirationRules(
            maxAge: self::readInt(
                $entry,
                PasswordPolicyOid::NAME_PWD_MAX_AGE,
            ),
            expireWarning: self::readInt(
                $entry,
                PasswordPolicyOid::NAME_PWD_EXPIRE_WARNING,
            ),
            graceAuthnLimit: self::readInt(
                $entry,
                PasswordPolicyOid::NAME_PWD_GRACE_AUTHN_LIMIT,
            ),
            graceExpiry: self::readInt(
                $entry,
                PasswordPolicyOid::NAME_PWD_GRACE_EXPIRY,
            ),
            maxIdle: self::readInt(
                $entry,
                PasswordPolicyOid::NAME_PWD_MAX_IDLE,
            ),
        );
    }

    private static function readLockout(Entry $entry): PasswordLockoutRules
    {
        return new PasswordLockoutRules(
            enabled: self::readBool(
                $entry,
                PasswordPolicyOid::NAME_PWD_LOCKOUT,
            ),
            duration: self::readInt(
                $entry,
                PasswordPolicyOid::NAME_PWD_LOCKOUT_DURATION,
            ),
            maxFailure: self::readInt(
                $entry,
                PasswordPolicyOid::NAME_PWD_MAX_FAILURE,
            ),
            failureCountInterval: self::readInt(
                $entry,
                PasswordPolicyOid::NAME_PWD_FAILURE_COUNT_INTERVAL,
            ),
            maxRecordedFailure: self::readInt(
                $entry,
                PasswordPolicyOid::NAME_PWD_MAX_RECORDED_FAILURE,
            ),
            minDelay: self::readInt(
                $entry,
                PasswordPolicyOid::NAME_PWD_MIN_DELAY,
            ),
            maxDelay: self::readInt(
                $entry,
                PasswordPolicyOid::NAME_PWD_MAX_DELAY,
            ),
        );
    }

    /**
     * @return int<0, max>|null
     * @throws PasswordPolicyException
     */
    private static function readInt(
        Entry $entry,
        string $name,
    ): ?int {
        $value = $entry->get($name)?->firstValue();
        if ($value === null) {
            return null;
        }

        if (!ctype_digit($value)) {
            throw new PasswordPolicyException(sprintf(
                'pwdPolicy entry "%s" has invalid value "%s" for %s; expected a non-negative integer.',
                $entry->getDn()->toString(),
                $value,
                $name,
            ));
        }

        return max(
            0,
            (int) $value,
        );
    }

    private static function readBool(
        Entry $entry,
        string $name,
    ): ?bool {
        $value = $entry->get($name)?->firstValue();
        if ($value === null) {
            return null;
        }

        return match (strtoupper($value)) {
            'TRUE' => true,
            'FALSE' => false,
            default => throw new PasswordPolicyException(sprintf(
                'pwdPolicy entry "%s" has non-boolean value "%s" for %s.',
                $entry->getDn()->toString(),
                $value,
                $name,
            )),
        };
    }
}
