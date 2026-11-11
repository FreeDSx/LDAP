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

namespace FreeDSx\Ldap\Protocol\Decoder;

use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\AdminLimitExceededException;
use FreeDSx\Ldap\Exception\ProtocolException;

use function count;
use function sprintf;

/**
 * Decodes the attribute names a request selects (RFC 4511 4.5.1.8), which the read-entry controls reuse (RFC 4527).
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class AttributeSelectionDecoder
{
    /**
     * The most attribute names a received selection may hold.
     */
    public const MAX_ATTRIBUTES = 1000;

    /**
     * @return list<string>
     * @throws AdminLimitExceededException when the selection holds more names than the limit.
     * @throws ProtocolException
     */
    public function decode(SequenceType $selection): array
    {
        if (count($selection) > self::MAX_ATTRIBUTES) {
            throw new AdminLimitExceededException(sprintf(
                'The request selects more than %d attributes.',
                self::MAX_ATTRIBUTES,
            ));
        }

        $names = [];
        foreach ($selection->getChildren() as $name) {
            if (!$name instanceof OctetStringType) {
                throw new ProtocolException('An attribute selection must contain octet string values.');
            }
            $names[] = $name->getValue();
        }

        return $names;
    }
}
