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

namespace FreeDSx\Ldap\Protocol\Decoder\Response;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

/**
 * Decodes one type of extended response from the value its generic form carries.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ExtendedResponseValueDecoderInterface
{
    /**
     * @throws ProtocolException
     * @throws EncoderException
     */
    public function decode(
        ExtendedResponse $response,
        DecodeContext $context,
    ): ExtendedResponse;
}
