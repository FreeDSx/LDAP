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

namespace FreeDSx\Ldap\Protocol;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Bind\BindInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

class Authenticator
{
    /**
     * @param BindInterface[] $authenticators
     */
    public function __construct(private readonly array $authenticators = [])
    {
    }

    public function bind(LdapMessageRequest $request): TokenInterface
    {
        foreach ($this->authenticators as $authenticator) {
            if ($authenticator->supports($request)) {
                return $authenticator->bind($request);
            }
        }

        throw new OperationException(
            'The authentication type requested is not supported.',
            ResultCode::AUTH_METHOD_UNSUPPORTED
        );
    }
}
