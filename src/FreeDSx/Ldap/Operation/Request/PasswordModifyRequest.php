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
use FreeDSx\Asn1\Type\SequenceType;

/**
 * RFC 3062. A password modify extended request.
 *
 * PasswdModifyRequestValue ::= SEQUENCE {
 *     userIdentity    [0]  OCTET STRING OPTIONAL
 *     oldPasswd       [1]  OCTET STRING OPTIONAL
 *     newPasswd       [2]  OCTET STRING OPTIONAL }
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PasswordModifyRequest extends ExtendedRequest
{
    public function __construct(
        private ?string $userIdentity = null,
        private ?string $oldPassword = null,
        private ?string $newPassword = null,
    ) {
        parent::__construct(self::OID_PWD_MODIFY);
    }

    public function getUsername(): ?string
    {
        return $this->userIdentity;
    }

    public function setUsername(?string $username): self
    {
        $this->userIdentity = $username;

        return $this;
    }

    public function getNewPassword(): ?string
    {
        return $this->newPassword;
    }

    public function setNewPassword(?string $newPassword): self
    {
        $this->newPassword = $newPassword;

        return $this;
    }

    public function getOldPassword(): ?string
    {
        return $this->oldPassword;
    }

    public function setOldPassword(?string $oldPassword): self
    {
        $this->oldPassword = $oldPassword;

        return $this;
    }

    public function toAsn1(): SequenceType
    {
        $this->requestValue = Asn1::sequence();

        if ($this->userIdentity !== null) {
            $this->requestValue->addChild(Asn1::context(
                tagNumber: 0,
                type: Asn1::octetString($this->userIdentity),
            ));
        }
        if ($this->oldPassword !== null) {
            $this->requestValue->addChild(Asn1::context(
                tagNumber: 1,
                type: Asn1::octetString($this->oldPassword),
            ));
        }
        if ($this->newPassword !== null) {
            $this->requestValue->addChild(Asn1::context(
                tagNumber: 2,
                type: Asn1::octetString($this->newPassword),
            ));
        }

        return parent::toAsn1();
    }
}
