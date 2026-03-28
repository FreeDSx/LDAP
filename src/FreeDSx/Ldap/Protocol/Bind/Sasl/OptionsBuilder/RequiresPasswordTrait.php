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

namespace FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;

/**
 * Shared logic for validating that a password was returned for a SASL mechanism.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait RequiresPasswordTrait
{
    /**
     * @throws OperationException if the password is null (user not found or not allowed).
     */
    private function requirePassword(?string $password): string
    {
        if ($password === null) {
            throw new OperationException(
                'Invalid credentials.',
                ResultCode::INVALID_CREDENTIALS
            );
        }

        return $password;
    }
}
