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

namespace FreeDSx\Ldap\Server\Backend\Write\Operation\Linked;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkDelta;

/**
 * What a modify's linked changes amount to once replayed against what the owner links.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class SettledLinks
{
    /**
     * @param LinkDelta $delta The values to store, net of changes that cancel out.
     * @param list<Change> $changes The linked changes as the client supplied them.
     * @param array<string, int> $counts Values each attribute holds afterwards, by lowercased name, counted up to two.
     */
    public function __construct(
        public LinkDelta $delta = new LinkDelta(),
        public array $changes = [],
        public array $counts = [],
    ) {}
}
