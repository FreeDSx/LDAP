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

namespace FreeDSx\Ldap\Server\RequestHandler;

use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\AttributeSearchBindNameResolver;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverChain;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\DnBindNameResolver;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticator;
use FreeDSx\Ldap\Server\Backend\Write\WritableLdapBackendInterface;
use FreeDSx\Ldap\Server\HandlerFactoryInterface;
use FreeDSx\Ldap\ServerOptions;

/**
 * This is used by the server protocol handler to instantiate the possible user-land LDAP handlers (ie. handlers exposed
 * in the public API options).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class HandlerFactory implements HandlerFactoryInterface
{
    public function __construct(
        private readonly ServerOptions $options,
        private readonly WritableLdapBackendInterface $backend,
    ) {}

    /**
     * @inheritDoc
     */
    public function makePasswordAuthenticator(): PasswordAuthenticatableInterface
    {
        return $this->options->getPasswordAuthenticator()
            ?? new PasswordAuthenticator(
                $this->makeIdentityResolverChain(),
                $this->backend,
            );
    }

    public function makeIdentityResolverChain(): BindNameResolverInterface
    {
        $configured = $this->options->getIdentityResolver();

        return new BindNameResolverChain([
            new DnBindNameResolver(),
            $configured ?? new AttributeSearchBindNameResolver(),
        ]);
    }
}
