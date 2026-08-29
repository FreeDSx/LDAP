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

namespace FreeDSx\Ldap\Server\Backend\Write;

use FreeDSx\Ldap\Entry\Dn;

/**
 * Marks a write as loading an entry as supplied, rather than composing one for a client.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class BulkLoadOptions
{
    public function __construct(
        public Dn $actorDn = new Dn(''),
        public bool $replaceExisting = false,
    ) {}
}
