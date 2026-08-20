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
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Sasl\Options\ChallengeOptionsInterface;
use FreeDSx\Sasl\Options\SelectOptions;

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
    public function __construct(
        private string $mechanism,
        private readonly ?string $credentials = null,
        private readonly ?ChallengeOptionsInterface $options = null,
        private readonly ?SelectOptions $selectOptions = null,
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

    public function getOptions(): ?ChallengeOptionsInterface
    {
        return $this->options;
    }

    public function getSelectOptions(): ?SelectOptions
    {
        return $this->selectOptions;
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
            type: $sasl,
        );
    }

    /**
     * RFC 4511 4.2.1 gives an empty mechanism a meaning of its own, so nothing here is rejected.
     */
    protected function validate(): void {}
}
