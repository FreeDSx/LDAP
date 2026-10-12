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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\AccessControl\OperationTargetDn;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;

use function array_filter;
use function array_values;

/**
 * Refuses a request naming a DN the grammar rejects with invalidDNSyntax (RFC 4511 A.2).
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class TargetDnSyntaxMiddleware implements MiddlewareInterface
{
    /**
     * @throws OperationException
     */
    public function process(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
    ): ResponseStream {
        foreach ($this->namedDns($context->message->getRequest()) as $dn) {
            // An unparsed DN would otherwise fall back to a lowercased string and read as a missing entry.
            if (!Dn::isValid($dn)) {
                throw new OperationException(
                    'The request names a DN that is not valid.',
                    ResultCode::INVALID_DN_SYNTAX,
                );
            }
        }

        return $next->handle($context);
    }

    /**
     * The DN fields a request addresses entries by: its target or search base, and a rename's new superior.
     *
     * @return list<Dn>
     */
    private function namedDns(RequestInterface $request): array
    {
        $dns = [
            $request instanceof SearchRequest
                ? $request->getBaseDn()
                : OperationTargetDn::of($request),
        ];

        if ($request instanceof ModifyDnRequest) {
            $dns[] = $request->getNewParentDn();
        }

        return array_values(array_filter($dns));
    }
}
