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
use FreeDSx\Asn1\Type\SequenceType;

/**
 * Represents a base bind request. RFC 4511, 4.2
 *
 * BindRequest ::= [APPLICATION 0] SEQUENCE {
 *     version                 INTEGER (1 ..  127),
 *     name                    LDAPDN,
 *     authentication          AuthenticationChoice }
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
abstract class BindRequest implements RequestInterface
{
    protected const APP_TAG = 0;

    protected int $version = 3;

    protected string $username;

    public function setVersion(int $version): static
    {
        $this->version = $version;

        return $this;
    }

    public function getVersion(): int
    {
        return $this->version;
    }

    public function setUsername(string $username): static
    {
        $this->username = $username;

        return $this;
    }

    public function getUsername(): string
    {
        return $this->username;
    }

    public function toAsn1(): SequenceType
    {
        $this->validate();

        return Asn1::application(self::APP_TAG, Asn1::sequence(
            Asn1::integer($this->version),
            Asn1::octetString($this->username),
            $this->getAsn1AuthChoice(),
        ));
    }

    /**
     * Get the ASN1 AuthenticationChoice for the bind request.
     *
     * @return AbstractType<mixed>
     */
    abstract protected function getAsn1AuthChoice(): AbstractType;

    /**
     * This is called as the request is transformed to ASN1 to be encoded. If the request parameters are not valid
     * then the method should throw an exception.
     */
    abstract protected function validate(): void;
}
