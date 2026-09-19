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

namespace FreeDSx\Ldap\Server\Backend\Storage\Search\Options;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\Subentry\SubentryVisibility;

/**
 * Which entries a list reads: those below a base, one level or the whole subtree, with or without subentries.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ListScope
{
    public function __construct(
        public Dn $baseDn,
        public bool $subtree,
        public SubentryVisibility $subentries = SubentryVisibility::All,
    ) {}
}
