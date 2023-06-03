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

namespace FreeDSx\Ldap\Control;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Exception\PartialPduException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\LdapEncoder;

/**
 * Represents a password policy response. draft-behera-ldap-password-policy-09
 *
 * PasswordPolicyResponseValue ::= SEQUENCE {
 *     warning [0] CHOICE {
 *         timeBeforeExpiration [0] INTEGER (0 .. maxInt),
 *         graceAuthNsRemaining [1] INTEGER (0 .. maxInt) } OPTIONAL,
 *     error   [1] ENUMERATED {
 *         passwordExpired             (0),
 *         accountLocked               (1),
 *         changeAfterReset            (2),
 *         passwordModNotAllowed       (3),
 *         mustSupplyOldPassword       (4),
 *         insufficientPasswordQuality (5),
 *         passwordTooShort            (6),
 *         passwordTooYoung            (7),
 *         passwordInHistory           (8) } OPTIONAL }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PwdPolicyResponseControl extends Control
{
    private ?int $timeBeforeExpiration;

    private ?int $graceAuthRemaining;

    private ?int $error;

    public function __construct(
        ?int $timeBeforeExpiration = null,
        ?int $graceAuthRemaining = null,
        ?int $error = null
    ) {
        $this->timeBeforeExpiration = $timeBeforeExpiration;
        $this->graceAuthRemaining = $graceAuthRemaining;
        $this->error = $error;
        parent::__construct(self::OID_PWD_POLICY);
    }

    public function getTimeBeforeExpiration(): ?int
    {
        return $this->timeBeforeExpiration;
    }

    public function getGraceAttemptsRemaining(): ?int
    {
        return $this->graceAuthRemaining;
    }

    public function getError(): ?int
    {
        return $this->error;
    }

    /**
     * @throws ProtocolException
     * @throws EncoderException
     */
    public function toAsn1(): AbstractType
    {
        $response = Asn1::sequence();
        $warning = null;

        if ($this->graceAuthRemaining !== null && $this->timeBeforeExpiration !== null) {
            throw new ProtocolException('The password policy response cannot have both a time expiration and a grace auth value.');
        }
        if ($this->timeBeforeExpiration !== null) {
            $warning = Asn1::context(
                tagNumber: 0,
                type: Asn1::sequence(
                    Asn1::context(
                        tagNumber: 0,
                        type: Asn1::integer($this->timeBeforeExpiration)
                    )
                )
            );
        }
        if ($this->graceAuthRemaining !== null) {
            $warning = Asn1::context(
                tagNumber: 0,
                type: Asn1::sequence(Asn1::context(
                    tagNumber: 1,
                    type: Asn1::integer($this->graceAuthRemaining)
                ))
            );
        }

        if ($warning !== null) {
            $response->addChild($warning);
        }
        if ($this->error !== null) {
            $response->addChild(Asn1::context(
                tagNumber: 1,
                type: Asn1::enumerated($this->error)
            ));
        }
        $this->controlValue = $response;

        return parent::toAsn1();
    }

    /**
     * {@inheritDoc}
     * @throws EncoderException
     * @throws PartialPduException
     */
    public static function fromAsn1(AbstractType $type): static
    {
        /** @var SequenceType $response */
        $response = self::decodeEncodedValue($type);

        $error = null;
        $timeBeforeExpiration = null;
        $graceAttemptsRemaining = null;

        $encoder = new LdapEncoder();
        foreach ($response->getChildren() as $child) {
            if (!$child instanceof IncompleteType) {
                throw new ProtocolException('The ASN1 structure for the pwdPolicy control is malformed.');
            }
            if ($child->getTagNumber() === 0) {
                $warnings = $encoder->complete($child, AbstractType::TAG_TYPE_SEQUENCE, [
                    AbstractType::TAG_CLASS_CONTEXT_SPECIFIC => [
                        0 => AbstractType::TAG_TYPE_INTEGER,
                        1 => AbstractType::TAG_TYPE_INTEGER,
                    ],
                ]);
                foreach ($warnings->getChildren() as $warning) {
                    if ($warning->getTagNumber() === 0) {
                        $timeBeforeExpiration = $warning->getValue();
                        break;
                    } elseif ($warning->getTagNumber() === 1) {
                        $graceAttemptsRemaining = $warning->getValue();
                        break;
                    }
                }
            } elseif ($child->getTagNumber() === 1) {
                $error = $encoder->complete($child, AbstractType::TAG_TYPE_ENUMERATED)->getValue();
            }
        }
        $control = new static(
            $timeBeforeExpiration,
            $graceAttemptsRemaining,
            $error
        );

        return self::mergeControlData(
            $control,
            $type
        );
    }
}
