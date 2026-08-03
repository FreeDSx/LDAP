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

namespace FreeDSx\Ldap\Server\AccessControl;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;

/**
 * Resolves the primary target DN an operation request acts on.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class OperationTargetDn
{
    public static function of(RequestInterface $request): ?Dn
    {
        return match (true) {
            $request instanceof AddRequest => $request->getEntry()->getDn(),
            $request instanceof ModifyRequest,
            $request instanceof DeleteRequest,
            $request instanceof ModifyDnRequest,
            $request instanceof CompareRequest => $request->getDn(),
            default => null,
        };
    }

    /**
     * Where a rename leaves the entry, derived the same way the backend derives it.
     */
    public static function resultOf(ModifyDnRequest $request): Dn
    {
        return Dn::fromRdn(
            $request->getNewRdn(),
            $request->getNewParentDn() ?? $request->getDn()->getParent(),
        );
    }
}
