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

namespace FreeDSx\Ldap\Server\Backend\Storage\Capability;

use Closure;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkDelta;

/**
 * Storage that ties a linked value to the entry it names on write, which must wait while entries are still being placed.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface DeferredLinksInterface
{
    /**
     * Writes the entry through the callback with its linked values held back and its current links left in place.
     *
     * @param Closure(Entry, LinkDelta): void $write
     */
    public function deferLinks(
        string $uuid,
        Entry $entry,
        Closure $write,
    ): void;

    /**
     * Links the next batch of held back values to the entries they now name, returning false once none were left.
     */
    public function linkDeferred(): bool;
}
