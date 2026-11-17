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

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Protocol\Factory\HandlerId;
use FreeDSx\Ldap\Protocol\Factory\HandlerRouteResolverInterface;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\AssertionEvaluator;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;

/**
 * Rejects a search whose RFC 4528 assertion control does not match its base entry, before the search runs.
 *
 * A compare or a write evaluates its assertion against the entry it reads itself, so the two are one atomic action.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class AssertionMiddleware implements MiddlewareInterface
{
    public function __construct(
        private AssertionEvaluator $evaluator,
        private HandlerRouteResolverInterface $routes,
    ) {}

    /**
     * @throws OperationException
     */
    public function process(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
    ): ResponseStream {
        $message = $context->message;
        $request = $message->getRequest();

        # Paged search runs once at the start; continuation pages resume the same operation, so the assertion
        # (a precondition of that single execution) is only evaluated on the first page.
        if ($this->isPagingContinuation($message)) {
            return $next->handle($context);
        }

        $target = $request instanceof SearchRequest
            ? $request->getBaseDn()
            : null;

        if ($target !== null) {
            $this->evaluator->assertSatisfied(
                $target,
                $message->controls(),
                $context->tokenOrFail(),
            );
        }

        return $next->handle($context);
    }

    /**
     * Whether the request is a later page of a paged search.
     */
    private function isPagingContinuation(LdapMessageRequest $message): bool
    {
        $paging = $message->controls()->get(Control::OID_PAGING);

        return $paging instanceof PagingControl
            && $paging->getCookie() !== ''
            && $this->routes->routeIdFor(
                $message->getRequest(),
                $message->controls(),
            ) === HandlerId::Paging;
    }
}
