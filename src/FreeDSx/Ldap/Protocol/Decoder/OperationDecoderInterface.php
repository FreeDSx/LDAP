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

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\ProtocolElementInterface;

/**
 * Decodes one kind of request or response from the operation a received message carries.
 *
 * @template-covariant T of ProtocolElementInterface
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface OperationDecoderInterface
{
    /**
     * @param AbstractType<mixed> $type
     * @return T
     * @throws ProtocolException
     * @throws EncoderException
     */
    public function decode(
        AbstractType $type,
        DecodeContext $context,
    ): ProtocolElementInterface;
}
