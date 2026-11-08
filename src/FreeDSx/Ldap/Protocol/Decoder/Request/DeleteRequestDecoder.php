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

namespace FreeDSx\Ldap\Protocol\Decoder\Request;

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\OperationDecoderInterface;

use function sprintf;

/**
 * Decodes a delete request (RFC 4511 4.8).
 *
 * @implements OperationDecoderInterface<DeleteRequest>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class DeleteRequestDecoder implements OperationDecoderInterface
{
    private const APP_TAG = 10;

    /**
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     */
    public function decode(
        AbstractType $type,
        DecodeContext $context,
    ): DeleteRequest {
        if (!$type instanceof OctetStringType || $type->getTagClass() !== AbstractType::TAG_CLASS_APPLICATION) {
            throw new ProtocolException('The delete request must be an octet string with an application tag class.');
        }
        if ($type->getTagNumber() !== self::APP_TAG) {
            throw new ProtocolException(sprintf(
                'The delete request must have an app tag of %s, received: %s',
                self::APP_TAG,
                $type->getTagNumber(),
            ));
        }

        return new DeleteRequest($type->getValue());
    }
}
