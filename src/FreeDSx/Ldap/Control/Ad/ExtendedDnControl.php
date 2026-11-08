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
 * Used to represent the Extended DN control.
 *
 * @api
 *
 * @see https://msdn.microsoft.com/en-us/library/cc223349.aspx
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ExtendedDnControl extends Control
{
    public function __construct(
        private bool $useHexFormat = false,
        string $controlType = self::OID_EXTENDED_DN,
        bool $criticality = false,
    ) {
        parent::__construct(
            controlType: $controlType,
            criticality: $criticality,
        );
    }

    public function getUseHexFormat(): bool
    {
        return $this->useHexFormat;
    }

    public function setUseHexFormat(bool $useHexFormat): self
    {
        $this->useHexFormat = $useHexFormat;

        return $this;
    }

    public function toAsn1(): SequenceType
    {
        $useHexFormat = $this->useHexFormat ? 0 : 1;
        $this->controlValue = Asn1::sequence(Asn1::integer($useHexFormat));

        return parent::toAsn1();
    }
}
