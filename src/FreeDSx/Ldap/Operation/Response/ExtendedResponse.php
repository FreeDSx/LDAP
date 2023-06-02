<?php

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
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Exception\PartialPduException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\ProtocolElementInterface;

/**
 * RFC 4511, 4.12
 *
 * ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
 *     COMPONENTS OF LDAPResult,
 *         responseName     [10] LDAPOID OPTIONAL,
 *         responseValue    [11] OCTET STRING OPTIONAL }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ExtendedResponse extends LdapResult
{
    /**
     * RFC 4511, 4.4.1. Used by the server to notify the client it is terminating the LDAP session.
     */
    public const OID_NOTICE_OF_DISCONNECTION = '1.3.6.1.4.1.1466.20036';

    protected int $tagNumber = 24;

    protected ?string $responseName;

    protected AbstractType|ProtocolElementInterface|string|null $responseValue;

    public function __construct(
        LdapResult $result,
        ?string $responseName = null,
        ?string $responseValue = null
    ) {
        $this->responseValue = $responseValue;
        $this->responseName = $responseName;
        parent::__construct(
            $result->getResultCode(),
            $result->getDn(),
            $result->getDiagnosticMessage(),
            ...$result->getReferrals()
        );
    }

    /**
     * Get the OID name of the extended response.
     */
    public function getName(): ?string
    {
        return $this->responseName;
    }

    /**
     * Get the value of the extended response.
     */
    public function getValue(): ?string
    {
        return is_string($this->responseValue) ? $this->responseValue : null;
    }

    /**
     * {@inheritDoc}
     * @throws EncoderException
     */
    public static function fromAsn1(AbstractType $type): static
    {
        return new static(
            self::createLdapResult($type),
            ...self::parseExtendedResponse($type)
        );
    }

    /**
     * @throws ProtocolException
     * @throws EncoderException
     */
    public function toAsn1(): AbstractType
    {
        /** @var SequenceType $asn1 */
        $asn1 = parent::toAsn1();

        if ($this->responseName !== null) {
            $asn1->addChild(Asn1::context(
                tagNumber: 10,
                type: Asn1::octetString($this->responseName),
            ));
        }
        if ($this->responseValue !== null) {
            $encoder = new LdapEncoder();
            $value = $this->responseValue;
            if ($value instanceof AbstractType) {
                $value = $encoder->encode($value);
            } elseif ($value instanceof ProtocolElementInterface) {
                $value = $encoder->encode($value->toAsn1());
            }
            $asn1->addChild(Asn1::context(
                tagNumber: 11,
                type: Asn1::octetString($value),
            ));
        }

        return $asn1;
    }

    /**
     * @return array{0: ?string, 1: ?string}
     */
    protected static function parseExtendedResponse(AbstractType $type): array
    {
        $info = [0 => null, 1 => null];

        foreach ($type->getChildren() as $child) {
            if ($child->getTagNumber() === 10) {
                $info[0] = $child->getValue();
            } elseif ($child->getTagNumber() === 11) {
                $info[1] = $child->getValue();
            }
        }

        return $info;
    }

    /**
     * @throws ProtocolException
     * @throws EncoderException
     */
    protected static function createLdapResult(AbstractType $type): LdapResult
    {
        [$resultCode, $dn, $diagnosticMessage, $referrals] = self::parseResultData($type);

        return new LdapResult(
            $resultCode,
            $dn,
            $diagnosticMessage,
            ...$referrals
        );
    }

    /**
     * @throws ProtocolException
     * @throws EncoderException
     * @throws PartialPduException
     */
    protected static function decodeEncodedValue(AbstractType $type): ?AbstractType
    {
        if (!$type instanceof SequenceType) {
            throw new ProtocolException('The received control is malformed. Unable to get the encoded value.');
        }
        [1 => $value] = self::parseExtendedResponse($type);

        return $value === null
            ? null
            : (new LdapEncoder())->decode($value);
    }
}
