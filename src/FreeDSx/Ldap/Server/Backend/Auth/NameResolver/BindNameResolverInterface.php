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

use FreeDSx\Ldap\Entry\Entry;

/**
 * Translates a raw LDAP bind name into an Entry.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface BindNameResolverInterface
{
    /**
     * Resolve the bind name to an Entry, or return null if no match is found.
     */
    public function resolve(string $name): ?Entry;
}
