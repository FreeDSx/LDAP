<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpDs\Ldap\Control;

use PhpDs\Ldap\Asn1\Encoder\BerEncoder;
use PhpDs\Ldap\Asn1\Type\AbstractType;
use PhpDs\Ldap\Asn1\Type\SequenceType;

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
 * @todo Unsure how the decoding/encoding is handled for the Choice here.
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PwdPolicyResponseControl extends Control
{
    /**
     * @var int|null
     */
    protected $timeBeforeExpiration;

    /**
     * @var int|null
     */
    protected $graceAuthRemaining;

    /**
     * @var int|null
     */
    protected $error;

    /**
     * @param int|null $timeBeforeExpiration
     * @param int|null $graceAuthRemaining
     * @param int|null $error
     */
    public function __construct(?int $timeBeforeExpiration = null, ?int $graceAuthRemaining = null, ?int $error = null)
    {
        $this->timeBeforeExpiration = $timeBeforeExpiration;
        $this->graceAuthRemaining = $graceAuthRemaining;
        $this->error = $error;
        parent::__construct(self::OID_PWD_POLICY);
    }

    /**
     * @return int|null
     */
    public function getTimeBeforeExpiration() : ?int
    {
        return $this->timeBeforeExpiration;
    }

    /**
     * @return int|null
     */
    public function getGraceAttemptsRemaining() : ?int
    {
        return $this->graceAuthRemaining;
    }

    /**
     * @return int|null
     */
    public function getError() : ?int
    {
        return $this->error;
    }

    public function toAsn1(): AbstractType
    {
        // TODO: Implement toAsn1() method.
    }

    public static function fromAsn1(AbstractType $type)
    {
        /** @var SequenceType $response */
        $response = self::decodeEncodedValue($type);

        $error = null;
        $timeBeforeExpiration = null;
        $graceAttemptsRemaining = null;

        $encoder = new BerEncoder();
        foreach ($response->getChildren() as $child) {
            if ($child->getTagNumber() === 0) {
                /** @var ChoiceType $child */
                $warning = $child->getChild(0);
                if ($warning->getTagNumber() === 0) {
                    $timeBeforeExpiration = $warning->getValue();
                } elseif ($warning->getTagNumber() === 1) {
                    $graceAttemptsRemaining = $warning->getValue();
                }
            } elseif ($child->getTagNumber() === 1) {
                $error = $encoder->complete($child->getValue(), AbstractType::TAG_TYPE_ENUMERATED);
            }
        }
        $control = new self($timeBeforeExpiration, $graceAttemptsRemaining, $error);

        return self::mergeControlData($control, $type);
    }
}
