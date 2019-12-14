<?php
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
use FreeDSx\Ldap\Exception\BindException;

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
     * @var string
     */
    protected $mechanism;

    /**
     * @var string|null
     */
    protected $credentials;

    /**
     * @var array
     */
    protected $options;

    public function __construct(string $mechanism, ?string $credentials = null, array $options = [])
    {
        $this->username = '';
        $this->mechanism = $mechanism;
        $this->credentials = $credentials;
        $this->options = $options;
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

    public function getOptions(): array
    {
        return $this->options;
    }

    /**
     * {@inheritDoc}
     */
    protected function getAsn1AuthChoice(): AbstractType
    {
        $sasl = Asn1::sequence(Asn1::octetString($this->mechanism));
        if ($this->credentials !== null) {
            $sasl->addChild(Asn1::octetString($this->credentials));
        }

        return Asn1::context(3, $sasl);
    }

    /**
     * {@inheritDoc}
     */
    protected function validate(): void
    {
        if ($this->mechanism === '') {
            throw new BindException('The mechanism name cannot be empty.');
        }
    }
}
