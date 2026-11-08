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

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Asn1\Type\SetType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Search\Filter\FilterContainerInterface;

/**
 * Decodes an AND or an OR filter (RFC 4511 4.5.1.7) and each filter it encloses.
 *
 * @template T of FilterContainerInterface
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class FilterSetDecoder implements FilterShapeDecoderInterface
{
    /**
     * @param class-string<T> $filterClass the AND or OR filter to build.
     */
    public function __construct(private string $filterClass) {}

    /**
     * @return T
     */
    public function decode(
        AbstractType $type,
        FilterDecodeRun $run,
    ): FilterContainerInterface {
        if ($type instanceof IncompleteType) {
            $type = $run->context->complete(
                $type,
                AbstractType::TAG_TYPE_SET,
            );
        }
        if (!$type instanceof SetType) {
            throw new ProtocolException('The filter is malformed');
        }

        $filters = [];
        foreach ($type->getChildren() as $child) {
            $filters[] = $run->decodeEnclosed($child);
        }

        return new $this->filterClass(...$filters);
    }
}
