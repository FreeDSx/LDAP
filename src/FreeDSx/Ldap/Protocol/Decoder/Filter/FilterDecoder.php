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
use FreeDSx\Ldap\Search\Filter\FilterContainerInterface;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filter\NotFilter;

use function is_int;
use function sprintf;

/**
 * Decodes a received filter (RFC 4511 4.5.1.7), refusing one nested too deeply or holding too many items.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class FilterDecoder
{
    /**
     * The most AND, OR, or NOT filters a received filter may be nested within.
     */
    public const MAX_NESTING_DEPTH = 30;

    /**
     * The most items a received filter may hold, each substring part and each empty AND or OR counting as one.
     */
    public const MAX_ITEMS = 1000;

    /**
     * @param array<int, FilterShapeDecoderInterface> $decoders the decoder of each kind of filter, keyed by its tag.
     */
    public function __construct(private array $decoders) {}

    /**
     * Each call decodes a filter of its own, so its depth and items count from zero.
     *
     * @param AbstractType<mixed> $type
     * @throws FilterDepthExceededException
     * @throws FilterTooWideException
     * @throws ProtocolException
     * @throws EncoderException
     */
    public function decode(
        AbstractType $type,
        DecodeContext $context,
    ): FilterInterface {
        return $this->decodeWithin(
            $type,
            new FilterDecodeRun(
                $context,
                $this,
            ),
        );
    }

    /**
     * @param AbstractType<mixed> $type
     * @throws FilterDepthExceededException
     * @throws FilterTooWideException
     * @throws ProtocolException
     * @throws EncoderException
     */
    public function decodeWithin(
        AbstractType $type,
        FilterDecodeRun $run,
    ): FilterInterface {
        if ($run->depth() > self::MAX_NESTING_DEPTH) {
            throw new FilterDepthExceededException(sprintf(
                'The filter is nested more than %d levels deep.',
                self::MAX_NESTING_DEPTH,
            ));
        }

        $tagNumber = $type->getTagNumber();
        $decoder = is_int($tagNumber)
            ? ($this->decoders[$tagNumber] ?? null)
            : null;
        if ($decoder === null) {
            throw new ProtocolException(sprintf(
                'The received filter "%s" is not recognized.',
                $tagNumber,
            ));
        }

        $filter = $decoder->decode(
            $type,
            $run,
        );

        // An AND, OR, or NOT counted the items beneath it as it decoded them, and an empty AND or OR stands for one.
        $isItem = $filter instanceof FilterContainerInterface
            ? $filter->get() === []
            : !$filter instanceof NotFilter;
        if ($isItem) {
            $run->countItem($filter);
        }

        return $filter;
    }
}
