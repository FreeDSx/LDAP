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

namespace FreeDSx\Ldap\Server\Initialization\Requirement;

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashScheme;
use FreeDSx\Ldap\Server\Config\PasswordHashing;
use FreeDSx\Ldap\Server\Initialization\RequirementInterface;

use function constant;
use function defined;

/**
 * This PHP build must be able to hash passwords the way the server is configured to.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class PasswordHashingRequirement implements RequirementInterface
{
    public function __construct(private PasswordHashing $hashing) {}

    public function assertMet(): void
    {
        if ($this->hashing->getScheme() !== PasswordHashScheme::Argon2) {
            return;
        }

        if (!defined('PASSWORD_ARGON2ID')) {
            throw new RuntimeException(
                'This PHP build cannot hash argon2id; add ext-sodium or libargon2, or configure bcrypt hashing.',
            );
        }

        if (constant('PASSWORD_ARGON2_PROVIDER') !== 'sodium' || $this->hashing->getArgon2Threads() === 1) {
            return;
        }

        throw new RuntimeException('This PHP build hashes argon2id with libsodium, which supports one thread only.');
    }
}
