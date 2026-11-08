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
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Search\Filter\NotFilter;

use function count;

/**
 * Decodes a NOT filter (RFC 4511 4.5.1.7) and the filter it negates.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class NotFilterDecoder implements FilterShapeDecoderInterface
{
    public function decode(
        AbstractType $type,
        FilterDecodeRun $run,
    ): NotFilter {
        if ($type instanceof IncompleteType) {
            $type = $run->context->complete(
                $type,
                AbstractType::TAG_TYPE_SEQUENCE,
            );
        }
        if (!($type instanceof SequenceType && count($type) === 1)) {
            throw new ProtocolException('The not filter is malformed');
        }
        $child = $type->getChild(0);
        if ($child === null) {
            throw new ProtocolException('The "not" filter is malformed.');
        }

        return new NotFilter($run->decodeEnclosed($child));
    }
}
