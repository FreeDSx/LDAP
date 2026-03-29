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

namespace FreeDSx\Ldap\Server\Backend\Auth\NameResolver;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;

/**
 * The default bind-name resolver. Treats the bind name as a DN and delegates
 * to LdapBackendInterface::get().
 *
 * This covers the common convention where clients bind with a full DN such as
 * "cn=admin,dc=example,dc=com". For non-DN bind names (email addresses, bare
 * usernames, etc.) provide a custom BindNameResolverInterface implementation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class DnBindNameResolver implements BindNameResolverInterface
{
    public function __construct(
        private readonly LdapBackendInterface $backend,
    ) {
    }

    public function resolve(string $name): ?Entry
    {
        return $this->backend->get(new Dn($name));
    }
}
