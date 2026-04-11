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
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class DnBindNameResolver implements BindNameResolverInterface
{
    public function resolve(
        string $name,
        LdapBackendInterface $backend,
    ): ?Entry {
        return $backend->get(new Dn($name));
    }
}
