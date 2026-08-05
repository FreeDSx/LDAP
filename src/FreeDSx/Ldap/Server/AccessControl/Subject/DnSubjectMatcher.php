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
 * Matches a specific bound DN (case-insensitive).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class DnSubjectMatcher implements SubjectMatcherInterface
{
    private readonly string $normalizedDn;

    public function __construct(string $dn)
    {
        $this->normalizedDn = (new Dn($dn))->normalize()->toString();
    }

    public function matches(
        TokenInterface $token,
        ?Dn $targetDn,
    ): bool {
        if (!$token instanceof AuthenticatedTokenInterface) {
            return false;
        }

        return $token->getResolvedDn()->normalize()->toString() === $this->normalizedDn;
    }
}
