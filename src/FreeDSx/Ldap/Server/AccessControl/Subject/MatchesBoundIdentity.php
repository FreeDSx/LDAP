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

namespace FreeDSx\Ldap\Server\AccessControl\Subject;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Answers whether a token's bound DN is the given target entry (case-insensitive), the shared notion of "self".
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait MatchesBoundIdentity
{
    /**
     * Note: Without a target there is nothing to be the same as, and only an authenticated token has a bound DN.
     *
     * @param TokenInterface $token
     * @param Dn|null $target
     * @return bool
     */
    private function isBoundIdentity(
        TokenInterface $token,
        ?Dn $target,
    ): bool {
        return $target !== null
            && $token instanceof AuthenticatedTokenInterface
            && $token->getResolvedDn()->normalize()->toString() === $target->normalize()->toString();
    }
}
