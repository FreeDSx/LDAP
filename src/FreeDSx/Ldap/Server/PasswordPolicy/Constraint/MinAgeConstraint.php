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

namespace FreeDSx\Ldap\Server\PasswordPolicy\Constraint;

use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Clock\ClockInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\PasswordPolicyOutcome;

/**
 * Denies a self-service change attempted within pwdMinAge seconds of the last password change.
 *
 * pwdMinAge restricts the user, not administrative resets, so non-self changes are exempt (draft-behera-10 §7.2).
 */
final readonly class MinAgeConstraint implements PasswordChangeConstraint
{
    public function __construct(private ClockInterface $clock) {}

    public function check(PasswordChangeAttempt $attempt): ?PasswordPolicyOutcome
    {
        $minAge = $attempt->policy->change->minAge;
        $changedAt = $attempt->state->changedAt;
        if (!$attempt->isSelf || $minAge === null || $minAge === 0 || $changedAt === null) {
            return null;
        }

        // draft-behera-11 §7.8: an identity that must change its password is exempt, since the reset gate
        // leaves it no other operation and the two rules would otherwise trap the account.
        if ($attempt->state->mustChangeUnder($attempt->policy)) {
            return null;
        }

        $age = $this->clock->now()->getTimestamp() - $changedAt->getTimestamp();
        if ($age >= $minAge) {
            return null;
        }

        return PasswordPolicyOutcome::deny(
            PwdPolicyError::PASSWORD_TOO_YOUNG,
            ResultCode::CONSTRAINT_VIOLATION,
            'Password was changed too recently.',
        );
    }
}
