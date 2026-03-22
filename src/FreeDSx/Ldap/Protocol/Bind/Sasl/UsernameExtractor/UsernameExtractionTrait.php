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

namespace FreeDSx\Ldap\Protocol\Bind\Sasl\UsernameExtractor;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Sasl\Message;

/**
 * Shared logic for validating and returning a username value extracted from SASL credentials.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait UsernameExtractionTrait
{
    /**
     * @throws OperationException if the named field is not a non-empty string.
     */
    private function requireUsername(
        Message $message,
        string $field,
        string $mechanism
    ): string {
        $value = $message->get($field);

        if (!is_string($value) || $value === '') {
            throw new OperationException(
                sprintf('The %s credentials did not contain a username.', $mechanism),
                ResultCode::PROTOCOL_ERROR
            );
        }

        return $value;
    }
}
