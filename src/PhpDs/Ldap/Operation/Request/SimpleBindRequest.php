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
use PhpDs\Ldap\Exception\BindException;
use PhpDs\Ldap\Exception\InvalidArgumentException;

/**
 * Represents a simple bind request consisting of a username (dn, etc) and a password.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SimpleBindRequest extends BindRequest
{
    /**
     * @var string
     */
    protected $password;

    /**
     * @param string $username
     * @param string $password
     * @param int $version
     */
    public function __construct(string $username, string $password, int $version = 3)
    {
        $this->username = $username;
        $this->password = $password;
        $this->version = $version;
    }

    /**
     * @return string
     */
    public function getPassword() : string
    {
        return $this->password;
    }

    /**
     * @param string $password
     * @return $this
     */
    public function setPassword(string $password)
    {
        $this->password = $password;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    protected function getAsn1AuthChoice(): AbstractType
    {
        return Asn1::context(0, Asn1::octetString($this->password));
    }

    /**
     * {@inheritdoc}
     */
    protected function validate(): void
    {
        if (empty($this->username) || empty($this->password)) {
            throw new BindException('A simple bind must have a non-empty username and password.');
        }
    }
}
