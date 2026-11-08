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
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\ReadEntry\ReadEntryControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

/**
 * Decodes a pre-read or post-read request control (RFC 4527 3.1 and 3.2).
 *
 * @extends EncodedValueControlDecoder<ReadEntryControl>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ReadEntryControlDecoder extends EncodedValueControlDecoder
{
    /**
     * @param class-string<ReadEntryControl> $controlClass the pre-read or post-read control to build.
     */
    public function __construct(private string $controlClass) {}

    protected function decodeValue(
        AbstractType $value,
        DecodeContext $context,
    ): ReadEntryControl {
        if (!$value instanceof SequenceType) {
            throw new ProtocolException('A read-entry control value must be a sequence of attribute names.');
        }

        $attributes = [];
        foreach ($value->getChildren() as $child) {
            if (!$child instanceof OctetStringType) {
                throw new ProtocolException('A read-entry attribute selection must contain octet string values.');
            }
            $attributes[] = $child->getValue();
        }

        return new $this->controlClass(...$attributes);
    }
}
