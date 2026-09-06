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

namespace FreeDSx\Ldap\Server\Paging;

/**
 * Why a slice stopped being read. This decides where the next one resumes from.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum SliceEnd
{
    /**
     * Read to its end. The read itself says where it stopped.
     */
    case Complete;

    /**
     * A match exists past what the page may hold.
     */
    case FurtherMatch;

    /**
     * The page filled part-way through. The rest of the slice belongs to the next page.
     */
    case PageFull;

    /**
     * A match arrived with no position to resume from. Nothing further may be taken from this read.
     */
    case Unplaceable;
}
