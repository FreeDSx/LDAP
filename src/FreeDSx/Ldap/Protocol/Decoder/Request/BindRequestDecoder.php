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

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\BindRequest;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

use function is_int;
use function sprintf;

/**
 * Decodes a bind request (RFC 4511 4.2) into its simple, anonymous, or SASL form.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class BindRequestDecoder implements RequestDecoderInterface
{
    /**
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     * @throws EncoderException
     */
    public function decode(
        AbstractType $type,
        DecodeContext $context,
    ): BindRequest {
        if (!$type instanceof SequenceType) {
            throw new ProtocolException('The bind request in malformed');
        }
        $version = $type->getChild(0);
        $name = $type->getChild(1);
        $auth = $type->getChild(2);

        if ($version === null || $name === null || $auth === null) {
            throw new ProtocolException('The bind request in malformed');
        }
        if (!($version instanceof IntegerType && $name instanceof OctetStringType)) {
            throw new ProtocolException('The bind request in malformed');
        }
        $versionValue = $version->getValue();
        if (!is_int($versionValue)) {
            throw new ProtocolException('The bind request version is not an integer.');
        }

        if ($auth->getTagNumber() === 3) {
            return $this->saslBind(
                $auth,
                $context,
            )->setVersion($versionValue);
        }

        return $this->simpleBind(
            $auth,
            $name->getValue(),
            $versionValue,
        );
    }

    /**
     * @param AbstractType<mixed> $auth
     * @throws ProtocolException
     */
    private function simpleBind(
        AbstractType $auth,
        string $name,
        int $version,
    ): BindRequest {
        if ($auth->getTagNumber() !== 0) {
            throw new ProtocolException(sprintf(
                'The auth choice tag %s in the bind request is not supported.',
                $auth->getTagNumber(),
            ));
        }
        if (!($auth instanceof IncompleteType || $auth instanceof OctetStringType)) {
            throw new ProtocolException('The bind request auth choice is malformed.');
        }
        $authValue = $auth->getValue();

        if ($authValue === '') {
            return new AnonBindRequest(
                $name,
                $version,
            );
        }

        return new SimpleBindRequest(
            $name,
            $authValue,
            $version,
        );
    }

    /**
     * @param AbstractType<mixed> $auth
     * @throws ProtocolException
     * @throws EncoderException
     */
    private function saslBind(
        AbstractType $auth,
        DecodeContext $context,
    ): SaslBindRequest {
        if ($auth instanceof IncompleteType) {
            $auth = $context->complete(
                $auth,
                AbstractType::TAG_TYPE_SEQUENCE,
            );
        }
        $mechanism = $auth->getChild(0);
        if (!$mechanism instanceof OctetStringType) {
            throw new ProtocolException('The SASL mechanism in the bind request is malformed.');
        }
        $credentials = $auth->getChild(1);

        return new SaslBindRequest(
            $mechanism->getValue(),
            $credentials instanceof OctetStringType ? $credentials->getValue() : null,
        );
    }
}
