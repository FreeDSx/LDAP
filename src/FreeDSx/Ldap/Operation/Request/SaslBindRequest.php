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

namespace FreeDSx\Ldap\Operation\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\LdapEncoder;

/**
 * Represents a SASL bind request consisting of a mechanism challenge / response.
 *
 *  AuthenticationChoice ::= CHOICE {
 *     simple                  [0] OCTET STRING,
 *     -- 1 and 2 reserved
 *     sasl                    [3] SaslCredentials,
 *     ...  }
 *
 *  SaslCredentials ::= SEQUENCE {
 *     mechanism               LDAPString,
 *     credentials             OCTET STRING OPTIONAL }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SaslBindRequest extends BindRequest
{
    /**
     * @param array<string, mixed> $options
     */
    public function __construct(
        private string $mechanism,
        private readonly ?string $credentials = null,
        private readonly array $options = []
    ) {
        $this->username = '';
    }

    public function getMechanism(): string
    {
        return $this->mechanism;
    }

    public function setMechanism(string $mech): self
    {
        $this->mechanism = $mech;

        return $this;
    }

    public function getCredentials(): ?string
    {
        return $this->credentials;
    }

    /**
     * @return array<string, mixed>
     */
    public function getOptions(): array
    {
        return $this->options;
    }

    /**
     * @param AbstractType<mixed> $type
     * @return SaslBindRequest
     * @throws ProtocolException
     * @throws \FreeDSx\Asn1\Exception\EncoderException
     */
    public static function fromAsn1(AbstractType $type): SaslBindRequest
    {
        if ($type instanceof IncompleteType) {
            $type = (new LdapEncoder())->complete(
                $type,
                AbstractType::TAG_TYPE_SEQUENCE,
            );
        }
        $mechanism = $type->getChild(0);
        if (!$mechanism instanceof OctetStringType) {
            throw new ProtocolException('The SASL mechanism in the bind request is malformed.');
        }
        $credentials = $type->getChild(1);

        return new SaslBindRequest(
            $mechanism->getValue(),
            $credentials instanceof OctetStringType ? $credentials->getValue() : null,
        );
    }

    /**
     * {@inheritDoc}
     *
     * @return AbstractType<mixed>
     */
    protected function getAsn1AuthChoice(): AbstractType
    {
        $sasl = Asn1::sequence(Asn1::octetString($this->mechanism));
        if ($this->credentials !== null) {
            $sasl->addChild(Asn1::octetString($this->credentials));
        }

        return Asn1::context(
            tagNumber: 3,
            type: $sasl
        );
    }

    /**
     * @throws BindException
     */
    protected function validate(): void
    {
        if ($this->mechanism === '') {
            throw new BindException('The mechanism name cannot be empty.');
        }
    }
}
