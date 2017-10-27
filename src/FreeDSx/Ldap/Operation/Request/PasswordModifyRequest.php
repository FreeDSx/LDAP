<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Operation\Request;

use FreeDSx\Ldap\Asn1\Asn1;
use FreeDSx\Ldap\Asn1\Type\AbstractType;

/**
 * RFC 3062. A password modify extended request.
 *
 * PasswdModifyRequestValue ::= SEQUENCE {
 *     userIdentity    [0]  OCTET STRING OPTIONAL
 *     oldPasswd       [1]  OCTET STRING OPTIONAL
 *     newPasswd       [2]  OCTET STRING OPTIONAL }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PasswordModifyRequest extends ExtendedRequest
{
    /**
     * @var null|string
     */
    protected $userIdentity;

    /**
     * @var null|string
     */
    protected $oldPassword;

    /**
     * @var null|string
     */
    protected $newPassword;

    /**
     * @param null|string $userIdentity
     * @param null|string $oldPassword
     * @param null|string $newPassword
     */
    public function __construct(?string $userIdentity = null, ?string $oldPassword = null, ?string $newPassword = null)
    {
        $this->userIdentity = $userIdentity;
        $this->oldPassword = $oldPassword;
        $this->newPassword = $newPassword;
        parent::__construct(self::OID_PWD_MODIFY);
    }

    /**
     * @return null|string
     */
    public function getUsername() : ?string
    {
        return $this->userIdentity;
    }

    /**
     * @param null|string $username
     * @return $this
     */
    public function setUsername(?string $username)
    {
        $this->userIdentity = $username;

        return $this;
    }

    /**
     * @return null|string
     */
    public function getNewPassword() : ?string
    {
        return $this->newPassword;
    }

    /**
     * @param null|string $newPassword
     * @return $this
     */
    public function setNewPassword(?string $newPassword)
    {
        $this->newPassword = $newPassword;

        return $this;
    }

    /**
     * @return null|string
     */
    public function getOldPassword() : ?string
    {
        return $this->oldPassword;
    }

    /**
     * @param null|string $oldPassword
     * @return $this
     */
    public function setOldPassword(?string $oldPassword)
    {
        $this->oldPassword = $oldPassword;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $this->requestValue = Asn1::sequence();

        if ($this->userIdentity !== null) {
            $this->requestValue->addChild(Asn1::context(0, Asn1::octetString($this->userIdentity)));
        }
        if ($this->oldPassword !== null) {
            $this->requestValue->addChild(Asn1::context(1, Asn1::octetString($this->oldPassword)));
        }
        if ($this->newPassword !== null) {
            $this->requestValue->addChild(Asn1::context(2, Asn1::octetString($this->newPassword)));
        }

        return parent::toAsn1();
    }
}
