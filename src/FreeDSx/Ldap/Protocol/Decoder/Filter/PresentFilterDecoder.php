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
use FreeDSx\Ldap\Protocol\Decoder\FieldValueTrait;
use FreeDSx\Ldap\Search\Filter\PresentFilter;

/**
 * Decodes a present filter (RFC 4511 4.5.1.7.5).
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class PresentFilterDecoder implements FilterShapeDecoderInterface
{
    use FieldValueTrait;

    public function decode(
        AbstractType $type,
        FilterDecodeRun $run,
    ): PresentFilter {
        if ($type instanceof IncompleteType) {
            $type = $run->context->complete(
                $type,
                AbstractType::TAG_TYPE_OCTET_STRING,
            );
        }

        return new PresentFilter(self::stringOf(
            $type,
            'The present filter is malformed',
        ));
    }
}
