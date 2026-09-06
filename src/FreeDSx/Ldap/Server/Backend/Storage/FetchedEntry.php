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
use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageCursor;

/**
 * One entry, paired with the point a later read resumes from once this one is taken.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class FetchedEntry
{
    /**
     * @param ?PageCursor $cursor null when the read cannot say where it is.
     */
    public function __construct(
        public Entry $entry,
        public ?PageCursor $cursor = null,
    ) {}
}
