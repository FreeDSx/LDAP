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
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\AccessControl\OperationTargetDn;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;

/**
 * Refuses with invalidDNSyntax a request naming a DN the grammar rejects or that is not UTF-8 (RFC 4511 4.1.2, A.2).
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
        $request = $context->message->getRequest();

        foreach (OperationTargetDn::named($request) as $dn) {
            self::assertUsable($dn);
        }
        if ($request instanceof ModifyDnRequest && !OperationTargetDn::resultOf($request)->isUtf8()) {
            self::refuse('The new RDN is not encoded as UTF-8.');
        }

        return $next->handle($context);
    }

    /**
     * @throws OperationException
     */
    private static function assertUsable(Dn $dn): void
    {
        // An unparsed DN would otherwise fall back to a lowercased string and read as a missing entry.
        if (!Dn::isValid($dn)) {
            self::refuse('The request names a DN that is not valid.');
        }
        // Parsing alone accepts octets that are not UTF-8, whether sent raw or as hexpairs.
        if (!$dn->isUtf8()) {
            self::refuse('The request names a DN that is not encoded as UTF-8.');
        }
    }

    /**
     * @throws OperationException
     */
    private static function refuse(string $message): never
    {
        throw new OperationException(
            $message,
            ResultCode::INVALID_DN_SYNTAX,
        );
    }
}
