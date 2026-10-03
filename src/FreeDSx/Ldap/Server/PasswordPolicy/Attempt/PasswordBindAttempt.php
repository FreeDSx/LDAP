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

namespace FreeDSx\Ldap\Server\PasswordPolicy\Attempt;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;

/**
 * Inputs for a single bind being evaluated against the password policy.
 */
final readonly class PasswordBindAttempt
{
    /**
     * @param string $uuid The entryUUID of the entry the bind read.
     */
    public function __construct(
        public string $name,
        public Dn $dn,
        public string $uuid,
        public UserPasswordState $state,
        public PasswordPolicy $policy,
    ) {}
}
