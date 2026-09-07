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

namespace FreeDSx\Ldap\Server\Proxy;

use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;

/**
 * Ends the upstream session for a bind the proxy did not carry through.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ProxyBindResetMiddleware implements MiddlewareInterface
{
    public function __construct(
        private ServerAuthorization $authorization,
        private ProxyUpstreamSession $session,
    ) {}

    /**
     * {@inheritDoc}
     */
    public function process(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
    ): ResponseStream {
        if (!$this->authorization->isAuthenticationRequest($context->message->getRequest())) {
            return $next->handle($context);
        }

        try {
            return $next->handle($context);
        } finally {
            // RFC 4511 §4.2.1 leaves a session anonymous when its bind does not succeed.
            if (!$this->authorization->isAuthenticated()) {
                $this->session->reset();
            }
        }
    }
}
