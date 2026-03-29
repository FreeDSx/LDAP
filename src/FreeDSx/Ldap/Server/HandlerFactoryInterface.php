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

use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;

/**
 * Responsible for instantiating classes needed by the core server logic.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface HandlerFactoryInterface
{
    /**
     * Return the configured backend, or a GenericBackend no-op if none is set.
     */
    public function makeBackend(): LdapBackendInterface;

    /**
     * Return the configured filter evaluator, or the default FilterEvaluator.
     */
    public function makeFilterEvaluator(): FilterEvaluatorInterface;

    /**
     * Return the optional root DSE handler, or null if not configured.
     */
    public function makeRootDseHandler(): ?RootDseHandlerInterface;

    /**
     * Build the write operation dispatcher.
     *
     * Explicit write handlers (registered via LdapServer::useWriteHandler()) are
     * added first (higher priority). The backend is appended as a fallback if it
     * implements WriteHandlerInterface.
     */
    public function makeWriteDispatcher(): WriteOperationDispatcher;

    /**
     * Return a PasswordAuthenticatableInterface for simple-bind and SASL PLAIN.
     *
     * Resolution order:
     *   1. An explicitly configured authenticator (via ServerOptions::setPasswordAuthenticator()).
     *   2. The backend itself, if it implements PasswordAuthenticatableInterface.
     *   3. The default PasswordAuthenticator, which reads userPassword from entries
     *      returned by the backend's get() method.
     */
    public function makePasswordAuthenticator(): PasswordAuthenticatableInterface;
}
