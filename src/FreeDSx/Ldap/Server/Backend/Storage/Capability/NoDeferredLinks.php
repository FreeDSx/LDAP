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
 * Stands in for storage that keeps linked values as written, which leaves nothing to tie to an entry later.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class NoDeferredLinks implements DeferredLinksInterface
{
    public function deferLinks(
        string $uuid,
        Entry $entry,
        Closure $write,
    ): void {
        $write(
            $entry,
            new LinkDelta(),
        );
    }

    public function linkDeferred(): bool
    {
        return false;
    }
}
