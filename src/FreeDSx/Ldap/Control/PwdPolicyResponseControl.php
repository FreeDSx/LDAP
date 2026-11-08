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
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;

/**
 * Represents a password policy response. draft-behera-ldap-password-policy-10
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
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PwdPolicyResponseControl extends Control
{
    public function __construct(
        private readonly ?int $timeBeforeExpiration = null,
        private readonly ?int $graceAuthRemaining = null,
        private readonly ?int $error = null,
    ) {
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
    public function toAsn1(): SequenceType
    {
        $response = Asn1::sequence();
        $warning = null;

        $timeBefore = $this->timeBeforeExpiration;
        $graceRemaining = $this->graceAuthRemaining;

        if ($timeBefore !== null && $graceRemaining !== null) {
            throw new ProtocolException('The password policy response cannot have both a time expiration and a grace auth value.');
        }
        if ($timeBefore !== null) {
            $warning = Asn1::context(
                tagNumber: 0,
                type: Asn1::sequence(
                    Asn1::context(
                        tagNumber: 0,
                        type: Asn1::integer($timeBefore),
                    ),
                ),
            );
        }
        if ($graceRemaining !== null) {
            $warning = Asn1::context(
                tagNumber: 0,
                type: Asn1::sequence(Asn1::context(
                    tagNumber: 1,
                    type: Asn1::integer($graceRemaining),
                )),
            );
        }

        if ($warning !== null) {
            $response->addChild($warning);
        }
        if ($this->error !== null) {
            $response->addChild(Asn1::context(
                tagNumber: 1,
                type: Asn1::enumerated($this->error),
            ));
        }
        $this->controlValue = $response;

        return parent::toAsn1();
    }
}
