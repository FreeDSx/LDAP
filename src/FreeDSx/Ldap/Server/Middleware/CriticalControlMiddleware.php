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

namespace FreeDSx\Ldap\Server\Middleware;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Protocol\Factory\HandlerRouteResolverInterface;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;

/**
 * Rejects requests carrying a critical control the resolved handler does not support (RFC 4511 §4.1.11).
 *
 * Note: A bind never reaches here, since it answers above this point. It runs the same check itself.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class CriticalControlMiddleware implements MiddlewareInterface
{
    public function __construct(
        private HandlerRouteResolverInterface $routeResolver,
        private CriticalControlValidator $validator = new CriticalControlValidator(),
    ) {}

    /**
     * @throws OperationException
     */
    public function process(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
    ): ResponseStream {
        $controls = $context->message->controls();

        $this->validator->assertSupportedForRoute(
            $this->routeResolver->routeIdFor(
                $context->message->getRequest(),
                $controls,
            ),
            $controls,
        );

        return $next->handle($context);
    }
}
