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
 * Represents an Expected Entry Count control. Defined in MS-ADTS 3.1.1.3.4.1.33. The control value request definition
 * is:
 *
 *  ExpectedEntryCountRequestValue ::= SEQUENCE {
 *      searchEntriesMin    INTEGER
 *      searchEntriesMax    INTEGER
 *  }
 *
 * @api
 *
 * @see https://msdn.microsoft.com/en-us/library/jj216720.aspx
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ExpectedEntryCountControl extends Control
{
    public function __construct(
        private int $min,
        private int $max,
    ) {
        parent::__construct(
            self::OID_EXPECTED_ENTRY_COUNT,
            true,
        );
    }

    public function getMaximum(): int
    {
        return $this->max;
    }

    public function setMaximum(int $max): self
    {
        $this->max = $max;

        return $this;
    }

    public function getMinimum(): int
    {
        return $this->min;
    }

    public function setMinimum(int $min): self
    {
        $this->min = $min;

        return $this;
    }

    public function toAsn1(): SequenceType
    {
        $this->controlValue = Asn1::sequence(
            Asn1::integer($this->min),
            Asn1::integer($this->max),
        );

        return parent::toAsn1();
    }
}
