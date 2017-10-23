<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpDs\Ldap\Operation\Request;

use PhpDs\Ldap\Asn1\Asn1;
use PhpDs\Ldap\Asn1\Type\AbstractType;

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

    /**
     * @var int
     */
    protected $version = 3;

    /**
     * @var string
     */
    protected $username;

    /**
     * @param int $version
     * @return $this
     */
    public function setVersion(int $version)
    {
        $this->version = $version;

        return $this;
    }

    /**
     * @return int
     */
    public function getVersion() : int
    {
        return $this->version;
    }

    /**
     * @param string $username
     * @return $this
     */
    public function setUsername(string $username)
    {
        $this->username = $username;

        return $this;
    }

    /**
     * @return string
     */
    public function getUsername() : string
    {
        return $this->username;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $this->validate();

        return Asn1::application(self::APP_TAG, Asn1::sequence(
            Asn1::integer($this->version),
            Asn1::ldapDn($this->username),
            $this->getAsn1AuthChoice()
        ));
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        // TODO: Implement fromAsn1() method.
    }

    /**
     * Get the ASN1 AuthenticationChoice for the bind request.
     *
     * @return AbstractType
     */
    abstract protected function getAsn1AuthChoice() : AbstractType;

    /**
     * This is called as the request is transformed to ASN1 to be encoded. If the request parameters are not valid
     * then the method should throw an exception.
     */
    abstract protected function validate() : void;
}
