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

namespace FreeDSx\Ldap\Protocol\Decoder\Control;

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\BooleanType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\ProtocolException;

/**
 * The type, criticality and raw value that every received control carries (RFC 4511 4.1.11).
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ControlFields
{
    public function __construct(
        public string $oid,
        public bool $criticality,
        public ?string $value,
    ) {}

    /**
     * @throws ProtocolException when the control has no type OID.
     */
    public static function of(SequenceType $control): self
    {
        $oid = null;
        $criticality = false;
        $value = null;

        // RFC 4511 4.1.1 does not forbid criticality on a response control.
        foreach ($control->getChildren() as $i => $child) {
            if ($child->getTagClass() !== AbstractType::TAG_CLASS_UNIVERSAL) {
                continue;
            }

            if ($i === 0 && $child instanceof OctetStringType) {
                $oid = $child->getValue();
            } elseif ($child instanceof BooleanType) {
                $criticality = $child->getValue();
            } elseif ($child instanceof OctetStringType) {
                $value = $child->getValue();
            }
        }

        if ($oid === null) {
            throw new ProtocolException('The received control is malformed. The control type OID is missing.');
        }

        return new self(
            $oid,
            $criticality,
            $value,
        );
    }

    /**
     * Sets the received fields on a control decoded from its value.
     *
     * @template T of Control
     * @param T $control
     * @return T
     */
    public function applyTo(Control $control): Control
    {
        $control->setTypeOid($this->oid);
        $control->setCriticality($this->criticality);
        $control->setValue($this->value);

        return $control;
    }
}
