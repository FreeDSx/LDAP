<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol\Factory;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\BindHandlerInterface;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerAnonBindHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerBindHandler;

/**
 * Determines the correct bind handler for the request.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerBindHandlerFactory
{
    /**
     * Get the bind handler specific to the request.
     *
     * @throws OperationException
     */
    public function get(RequestInterface $request): BindHandlerInterface
    {
        if ($request instanceof SimpleBindRequest) {
            return new ServerBindHandler();
        } elseif ($request instanceof AnonBindRequest) {
            return new ServerAnonBindHandler();
        } else {
            throw new OperationException(
                'The authentication type requested is not supported.',
                ResultCode::AUTH_METHOD_UNSUPPORTED
            );
        }
    }
}
