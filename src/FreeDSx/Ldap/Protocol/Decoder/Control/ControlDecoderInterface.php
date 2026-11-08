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

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

/**
 * Decodes a control from the sequence a received message carries for it.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ControlDecoderInterface
{
    /**
     * @throws ProtocolException
     * @throws EncoderException
     */
    public function decode(
        SequenceType $control,
        DecodeContext $context,
    ): Control;
}
