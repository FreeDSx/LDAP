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

namespace FreeDSx\Ldap\Server;

use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;

/**
 * Responsible for instantiating classes needed by the core server logic.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface HandlerFactoryInterface
{
    /**
     * Return a PasswordAuthenticatableInterface for simple-bind and SASL PLAIN.
     *
     * This is the authenticator configured via ServerOptions::setPasswordAuthenticator(), otherwise the default
     * PasswordAuthenticator, which reads userPassword from entries returned by the backend's get() method.
     */
    public function makePasswordAuthenticator(): PasswordAuthenticatableInterface;

    /**
     * Build the identity resolver chain: DnBindNameResolver first, then the configured resolver (or AttributeSearchBindNameResolver as the default fallback).
     */
    public function makeIdentityResolverChain(): BindNameResolverInterface;
}
