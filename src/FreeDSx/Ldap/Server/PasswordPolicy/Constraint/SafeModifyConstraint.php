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
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\PasswordPolicyOutcome;

/**
 * Requires the user to supply the existing password when pwdSafeModify is enabled.
 *
 * Safe-modify is a self-service requirement; administrative resets cannot supply the user's old password.
 */
final readonly class SafeModifyConstraint implements PasswordChangeConstraint
{
    /**
     * draft-behera-11 §8.2.1 pairs mustSupplyOldPassword with insufficientAccessRights.
     */
    public function check(PasswordChangeAttempt $attempt): ?PasswordPolicyOutcome
    {
        if (!$attempt->isSelf || $attempt->policy->change->safeModify !== true || ($attempt->oldPassword ?? '') !== '') {
            return null;
        }

        return PasswordPolicyOutcome::deny(
            PwdPolicyError::MUST_SUPPLY_OLD_PASSWORD,
            ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            'The existing password must be supplied.',
        );
    }
}
