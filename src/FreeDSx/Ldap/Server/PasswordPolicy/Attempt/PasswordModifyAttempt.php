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

use FreeDSx\Ldap\Entry\Entry;
use SensitiveParameter;

/**
 * Inputs for a single password modification being evaluated against policy.
 */
final readonly class PasswordModifyAttempt
{
    /**
     * @param bool $isNewEntry Whether the target is being created here, so its password values are the new ones
     *                         rather than any it previously held.
     */
    public function __construct(
        public Entry $target,
        #[SensitiveParameter]
        public string $newPassword,
        #[SensitiveParameter]
        public ?string $oldPassword,
        public bool $isSelf,
        public bool $passwordIsCleartext = true,
        public bool $isNewEntry = false,
    ) {}
}
