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

namespace FreeDSx\Ldap\Server\Backend\Storage\Contract;

use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;

/**
 * Streams the entries a scope selects. Dn parameters are always normalised (lowercased).
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ListEntryInterface
{
    /**
     * Lazily yield entries per $options scope: direct children when subtree is false; the base entry AND all descendants when true (RFC 4511 §4.5.1.2); empty baseDn lists from the tree root.
     */
    public function list(StorageListOptions $options): EntryStream;
}
