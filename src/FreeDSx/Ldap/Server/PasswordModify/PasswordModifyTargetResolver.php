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

namespace FreeDSx\Ldap\Server\PasswordModify;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;

/**
 * Resolves the entry an RFC 3062 request targets: the bound identity when no userIdentity is given, else the named one.
 */
final readonly class PasswordModifyTargetResolver
{
    public function __construct(
        private LdapBackendInterface $backend,
        private BindNameResolverInterface $identityResolver,
    ) {}

    /**
     * The targeted entry, or null when nothing matches.
     */
    public function find(
        PasswordModifyRequest $request,
        AuthenticatedTokenInterface $token,
    ): ?Entry {
        $userIdentity = $request->getUsername();

        if ($userIdentity === null || $userIdentity === '') {
            return $this->backend->get($token->getResolvedDn());
        }

        return $this->identityResolver->resolve(
            $userIdentity,
            $this->backend,
        );
    }
}
