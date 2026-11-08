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

namespace FreeDSx\Ldap\Protocol\Decoder\Control;

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Control\AssertionControl;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\Filter\FilterDecoder;

/**
 * Decodes an assertion control (RFC 4528) and the filter it carries.
 *
 * @extends EncodedValueControlDecoder<AssertionControl>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class AssertionControlDecoder extends EncodedValueControlDecoder
{
    public function __construct(private FilterDecoder $filters) {}

    protected function decodeValue(
        AbstractType $value,
        DecodeContext $context,
    ): AssertionControl {
        return new AssertionControl($this->filters->decode(
            $value,
            $context,
        ));
    }
}
