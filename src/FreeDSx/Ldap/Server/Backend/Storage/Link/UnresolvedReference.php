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

namespace FreeDSx\Ldap\Server\Backend\Storage\Link;

use FreeDSx\Ldap\Entry\Dn;

/**
 * A stored entry's attribute holding a value that names an entry the directory does not hold.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class UnresolvedReference
{
    public function __construct(
        public Dn $owner,
        public string $attribute,
    ) {}
}
