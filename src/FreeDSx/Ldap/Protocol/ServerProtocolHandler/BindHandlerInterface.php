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
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Used for handlers dealing with bind requests to send back tokens.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface BindHandlerInterface
{
    /**
     * Returns a token indicating the outcome of a bind request.
     *
     * @throws OperationException
     */
    public function handleBind(
        LdapMessageRequest $message,
        RequestHandlerInterface $dispatcher
    ): TokenInterface;
}
