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

namespace FreeDSx\Ldap\Control\Ad;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;

/**
 * Implements the AD PolicyHints control.
 *
 *  PolicyHintsRequestValue ::= SEQUENCE {
 *      Flags    INTEGER
 *  }
 *
 * @api
 *
 * @see https://msdn.microsoft.com/en-us/library/hh128228.aspx
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PolicyHintsControl extends Control
{
    public function __construct(private bool $isEnabled = true)
    {
        parent::__construct(
            self::OID_POLICY_HINTS,
            true,
        );
    }

    public function setIsEnabled(bool $isEnabled): self
    {
        $this->isEnabled = $isEnabled;

        return $this;
    }

    public function getIsEnabled(): bool
    {
        return $this->isEnabled;
    }

    public function toAsn1(): SequenceType
    {
        $this->controlValue = Asn1::sequence(Asn1::integer($this->isEnabled ? 1 : 0));

        return parent::toAsn1();
    }
}
