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

namespace FreeDSx\Ldap\Protocol\Decoder\Filter;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Exception\FilterDepthExceededException;
use FreeDSx\Ldap\Exception\FilterTooWideException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filter\SubstringFilter;

use function count;
use function max;
use function sprintf;

/**
 * The decode of one received filter: how deeply it has nested so far and how many items it has counted.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class FilterDecodeRun
{
    private int $depth = 0;

    private int $items = 0;

    public function __construct(
        public readonly DecodeContext $context,
        private readonly FilterDecoder $filters,
    ) {}

    /**
     * How many AND, OR, or NOT filters enclose the filter being decoded.
     */
    public function depth(): int
    {
        return $this->depth;
    }

    /**
     * Decodes a filter an AND, OR, or NOT encloses, one level deeper than the filter enclosing it.
     *
     * @param AbstractType<mixed> $type
     * @throws FilterDepthExceededException
     * @throws FilterTooWideException
     * @throws ProtocolException
     * @throws EncoderException
     */
    public function decodeEnclosed(AbstractType $type): FilterInterface
    {
        $this->depth++;
        try {
            return $this->filters->decodeWithin(
                $type,
                $this,
            );
        } finally {
            $this->depth--;
        }
    }

    /**
     * Counts an item, refusing the filter at the first item past the limit; a substring counts once per part.
     *
     * @throws FilterTooWideException
     */
    public function countItem(FilterInterface $item): void
    {
        $this->items += $item instanceof SubstringFilter
            ? self::partsOf($item)
            : 1;

        if ($this->items > FilterDecoder::MAX_ITEMS) {
            throw new FilterTooWideException(sprintf(
                'The filter holds more than %d items.',
                FilterDecoder::MAX_ITEMS,
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
