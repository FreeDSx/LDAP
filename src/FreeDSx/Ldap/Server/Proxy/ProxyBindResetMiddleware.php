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
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;

/**
 * Ends the upstream session whenever the proxied session holds no authenticated bind.
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
        // A bind refused before it reached the pipeline leaves the session anonymous while the upstream stays bound.
        $this->resetWithoutBind();

        if (!$this->authorization->isAuthenticationRequest($context->message->getRequest())) {
            return $next->handle($context);
        }

        try {
            return $next->handle($context);
        } finally {
            // RFC 4513 §4 leaves a session anonymous when its bind does not succeed.
            $this->resetWithoutBind();
        }
    }

    private function resetWithoutBind(): void
    {
        // The token's kind decides, as a session counts as authenticated whenever authentication is not required.
        if ($this->authorization->getToken() instanceof AuthenticatedTokenInterface) {
            return;
        }

        $this->session->reset();
    }
}
