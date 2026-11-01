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

namespace FreeDSx\Ldap\Protocol\Factory;

use FreeDSx\Ldap\Exception\FilterTooWideException;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filter\SubstringFilter;

use function count;
use function max;
use function sprintf;

/**
 * Counts the items of one received filter as it is decoded, refusing it at the first item past the limit.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class FilterItemTally
{
    private int $items = 0;

    /**
     * A substring item counts once for each of its parts.
     *
     * @throws FilterTooWideException
     */
    public function add(FilterInterface $item): void
    {
        $this->items += $item instanceof SubstringFilter
            ? self::partsOf($item)
            : 1;

        if ($this->items > FilterFactory::MAX_ITEMS) {
            throw new FilterTooWideException(sprintf(
                'The filter holds more than %d items.',
                FilterFactory::MAX_ITEMS,
            ));
        }
    }

    private static function partsOf(SubstringFilter $item): int
    {
        return max(
            1,
            count($item->getContains())
                + ($item->getStartsWith() === null ? 0 : 1)
                + ($item->getEndsWith() === null ? 0 : 1),
        );
    }
}
