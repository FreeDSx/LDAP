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
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Exception\PartialPduException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;

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
    private ?string $userIdentity;

    private ?string $oldPassword;

    private ?string $newPassword;

    public function __construct(
        ?string $userIdentity = null,
        ?string $oldPassword = null,
        ?string $newPassword = null
    ) {
        $this->userIdentity = $userIdentity;
        $this->oldPassword = $oldPassword;
        $this->newPassword = $newPassword;
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

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $this->requestValue = Asn1::sequence();

        if ($this->userIdentity !== null) {
            $this->requestValue->addChild(Asn1::context(
                tagNumber: 0,
                type: Asn1::octetString($this->userIdentity)
            ));
        }
        if ($this->oldPassword !== null) {
            $this->requestValue->addChild(Asn1::context(
                tagNumber: 1,
                type: Asn1::octetString($this->oldPassword)
            ));
        }
        if ($this->newPassword !== null) {
            $this->requestValue->addChild(Asn1::context(
                tagNumber: 2,
                type: Asn1::octetString($this->newPassword)
            ));
        }

        return parent::toAsn1();
    }

    /**
     * {@inheritDoc}
     * @throws EncoderException
     * @throws PartialPduException
     */
    public static function fromAsn1(AbstractType $type): static
    {
        $request = self::decodeEncodedValue($type);
        if ($request === null) {
            return new static();
        }
        if (!($request instanceof SequenceType)) {
            throw new ProtocolException('The password modify request is malformed.');
        }

        $userIdentity = null;
        $oldPasswd = null;
        $newPasswd = null;
        foreach ($request->getChildren() as $value) {
            if ($value->getTagClass() !== AbstractType::TAG_CLASS_CONTEXT_SPECIFIC) {
                throw new ProtocolException('The password modify request is malformed');
            }
            if ($value->getTagNumber() === 0) {
                $userIdentity = $value;
            } elseif ($value->getTagNumber() === 1) {
                $oldPasswd = $value;
            } elseif ($value->getTagNumber() === 2) {
                $newPasswd = $value;
            }
        }

        return new static(
            $userIdentity?->getValue(),
            $oldPasswd?->getValue(),
            $newPasswd?->getValue()
        );
    }
}
