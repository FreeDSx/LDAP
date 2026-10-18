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

namespace FreeDSx\Ldap\Server\Backend\Write\Operation;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkDelta;

/**
 * The entry a modify leaves behind and the linked values stored apart from it.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ModifiedEntry
{
    /**
     * @param LinkDelta $links Stated by every producer, since a plain delta rewrites the links from the entry itself.
     */
    public function __construct(
        public Entry $entry,
        public LinkDelta $links,
    ) {}
}
