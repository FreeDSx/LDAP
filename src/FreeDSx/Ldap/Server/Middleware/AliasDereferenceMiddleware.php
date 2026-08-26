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
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Directory\AliasResolver;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;

/**
 * Resolves an alias named as a search base (RFC 4511 4.5.1.3 derefFindingBaseObj).
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class AliasDereferenceMiddleware implements MiddlewareInterface
{
    public function __construct(
        private AliasResolver $aliasResolver,
        private AccessControlInterface $accessControl,
    ) {}

    /**
     * @throws OperationException
     */
    public function process(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
    ): ResponseStream {
        $request = $context->message->getRequest();

        if ($request instanceof SearchRequest) {
            $this->resolveBase($request, $context);
        }

        return $next->handle($context);
    }

    /**
     * @throws OperationException
     */
    private function resolveBase(
        SearchRequest $request,
        ServerRequestContext $context,
    ): void {
        $baseDn = $request->getBaseDn();
        if (!$this->derefsBase($request) || $baseDn === null || $baseDn->toString() === '') {
            return;
        }

        // Null covers both a base that is absent and one that is no alias; the backend answers for the first.
        $target = $this->aliasResolver->resolve($baseDn);
        if ($target === null) {
            return;
        }

        // Reported as missing rather than denied, which RFC 4511 4.1.9 permits to avoid disclosure.
        if (!$this->accessControl->isEntryVisible($context->tokenOrFail(), $target)) {
            throw new OperationException(
                'The search base does not exist.',
                ResultCode::NO_SUCH_OBJECT,
            );
        }

        $request->base($target->getDn());
    }

    private function derefsBase(SearchRequest $request): bool
    {
        $deref = $request->getDereferenceAliases();

        return $deref === SearchRequest::DEREF_FINDING_BASE_OBJECT
            || $deref === SearchRequest::DEREF_ALWAYS;
    }
}
