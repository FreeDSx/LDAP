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
use FreeDSx\Ldap\Protocol\LdapEncoder;

/**
 * RFC 4511, 4.13.
 *
 * IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
 *     responseName     [0] LDAPOID OPTIONAL,
 *     responseValue    [1] OCTET STRING OPTIONAL }
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class IntermediateResponse implements ResponseInterface
{
    public const OID_SYNC_INFO = '1.3.6.1.4.1.4203.1.9.1.4';

    protected const TAG_NUMBER = 25;

    private ?string $responseName;

    private ?string $responseValue;

    /**
     * @var AbstractType<mixed>|null
     */
    private ?AbstractType $responseValueToEncode = null;

    public function __construct(
        ?string $responseName,
        ?string $responseValue,
    ) {
        $this->responseName = $responseName;
        $this->responseValue = $responseValue;
    }

    public function getName(): ?string
    {
        return $this->responseName;
    }

    public function getValue(): ?string
    {
        return $this->responseValue;
    }

    public function toAsn1(): SequenceType
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
     * @param AbstractType<mixed> $valueToEncode
     */
    protected function setResponseValueToEncode(AbstractType $valueToEncode): void
    {
        $this->responseValueToEncode = $valueToEncode;
    }
}
