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

namespace FreeDSx\Ldap\Server\Backend\Storage;

use FreeDSx\Ldap\Entry\Entry;
use Generator;

/**
 * The result of a storage list() or backend search() call.
 *
 * Wraps the lazy entry generator together with a flag indicating whether the adapter has already applied the LDAP
 * filter exactly in its native query.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class EntryStream
{
    /**
     * @param Generator<Entry> $entries
     */
    public function __construct(
        public readonly Generator $entries,
        public readonly bool $isPreFiltered = false,
    ) {
    }
}
