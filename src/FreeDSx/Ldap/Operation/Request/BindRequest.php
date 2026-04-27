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
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;

/**
 * Represents a base bind request. RFC 4511, 4.2
 *
 * BindRequest ::= [APPLICATION 0] SEQUENCE {
 *     version                 INTEGER (1 ..  127),
 *     name                    LDAPDN,
 *     authentication          AuthenticationChoice }
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
            $this->getAsn1AuthChoice()
        ));
    }

    /**
     * {@inheritDoc}
     *
     * @param AbstractType<mixed> $type
     */
    public static function fromAsn1(AbstractType $type): BindRequest
    {
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
        $name = $name->getValue();

        if ($auth->getTagNumber() === 3) {
            return SaslBindRequest::fromAsn1($auth);
        }

        if ($auth->getTagNumber() !== 0) {
            throw new ProtocolException(sprintf(
                'The auth choice tag %s in the bind request is not supported.',
                $auth->getTagNumber()
            ));
        }
        if (!($auth instanceof IncompleteType || $auth instanceof OctetStringType)) {
            throw new ProtocolException('The bind request auth choice is malformed.');
        }
        $authValue = $auth->getValue();

        if ($authValue === '') {
            return new AnonBindRequest($name, $versionValue);
        }

        return new SimpleBindRequest(
            $name,
            $authValue,
            $versionValue,
        );
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
