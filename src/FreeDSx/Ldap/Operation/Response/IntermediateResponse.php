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

namespace FreeDSx\Ldap\Operation\Response;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\LdapEncoder;

/**
 * RFC 4511, 4.13.
 *
 * IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
 *     responseName     [0] LDAPOID OPTIONAL,
 *     responseValue    [1] OCTET STRING OPTIONAL }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class IntermediateResponse implements ResponseInterface
{
    public const OID_SYNC_INFO = '1.3.6.1.4.1.4203.1.9.1.4';

    protected const TAG_NUMBER = 25;

    private ?string $responseName;

    private ?string $responseValue;

    private ?AbstractType $responseValueToEncode = null;

    public function __construct(
        ?string $responseName,
        ?string $responseValue,
    ) {
        $this->responseName = $responseName;
        $this->responseValue = $responseValue;
    }

    protected function setResponseValueToEncode(AbstractType $valueToEncode): void
    {
        $this->responseValueToEncode = $valueToEncode;
    }

    public function getName(): ?string
    {
        return $this->responseName;
    }

    public function getValue(): ?string
    {
        return $this->responseValue;
    }

    /**
     * {@inheritDoc}
     */
    public static function fromAsn1(AbstractType $type): IntermediateResponse
    {
        if (!$type instanceof SequenceType) {
            throw new ProtocolException('The intermediate response is malformed');
        }

        $name = null;
        $value = null;
        foreach ($type->getChildren() as $child) {
            if ($child->getTagNumber() === 0 && $child->getTagClass() === AbstractType::TAG_CLASS_CONTEXT_SPECIFIC) {
                $name = $child->getValue();
            }
            if ($child->getTagNumber() === 1 && $child->getTagClass() === AbstractType::TAG_CLASS_CONTEXT_SPECIFIC) {
                $value = $child->getValue();
            }
        }

        $response = new self(
            $name === null ? null : (string) $name,
            $value === null ? null : (string) $value
        );

        if ($response->getName() === self::OID_SYNC_INFO) {
            $response = SyncInfoMessage::fromAsn1($type);
        }

        return $response;
    }

    private static function isNotValidResponseName(AbstractType $responseName): bool
    {
        return $responseName->getTagNumber() !== 0
            || $responseName->getTagClass() !== AbstractType::TAG_CLASS_CONTEXT_SPECIFIC;
    }

    private static function isNotValidResponseValue(AbstractType $responseValue): bool
    {
        return $responseValue->getTagNumber() !== 1
            || $responseValue->getTagClass() !== AbstractType::TAG_CLASS_CONTEXT_SPECIFIC;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $response = Asn1::sequence();

        if ($this->responseName !== null) {
            $response->addChild(Asn1::context(
                tagNumber: 0,
                type: Asn1::octetString($this->responseName),
            ));
        }

        $value = $this->responseValue;
        if ($this->responseValueToEncode !== null) {
            $encoder = new LdapEncoder();
            $value = $encoder->encode($this->responseValueToEncode);
        }

        $response->addChild(Asn1::context(
            tagNumber: 1,
            type: Asn1::octetString((string) $value),
        ));

        return Asn1::application(
            tagNumber: self::TAG_NUMBER,
            type: $response,
        );
    }

    /**
     * @param array<int, array<int, int|class-string>> $tagMap
     * @throws ProtocolException
     */
    protected static function decodeEncodedValue(
        AbstractType $type,
        array $tagMap
    ): AbstractType {
        $responseValue = $type->getChild(1);

        if ($responseValue == null || self::isNotValidResponseValue($responseValue)) {
            throw new ProtocolException(
                'The intermediate response either contains no value or is not an octet string.'
            );
        }

        return (new LdapEncoder())
            ->decode(
                $responseValue->getValue(),
                $tagMap
            );
    }

    /**
     * @throws ProtocolException
     */
    protected static function decodeResponseName(AbstractType $type): string
    {
        $responseName = $type->getChild(0);

        if ($responseName === null || self::isNotValidResponseName($responseName)) {
            throw new ProtocolException(
                'Expected a responseName value with a tag of 0 and a context specific class type.'
            );
        }

        return $responseName->getValue();
    }
}
