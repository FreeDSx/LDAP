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

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\BindRequest;
use FreeDSx\Ldap\Operation\ResultCode;

trait BindVersionValidatorTrait
{
    /**
     * @throws OperationException
     */
    private static function validateVersion(BindRequest $request): void
    {
        # Per RFC 4.2, a result code of protocol error must be sent back for unsupported versions.
        if ($request->getVersion() !== 3) {
            throw new OperationException(
                'Only LDAP version 3 is supported.',
                ResultCode::PROTOCOL_ERROR
            );
        }
    }
}
