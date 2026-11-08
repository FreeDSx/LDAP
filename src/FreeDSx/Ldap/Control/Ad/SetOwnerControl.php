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
 * Implements the AD SetOwner control.
 *
 *   SID octetString
 *
 * @api
 *
 * https://msdn.microsoft.com/en-us/library/dn392490.aspx
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SetOwnerControl extends Control
{
    public function __construct(private string $sid)
    {
        $this->sid = $sid;
        parent::__construct(
            self::OID_SET_OWNER,
            true,
        );
    }

    public function setSid(string $sid): self
    {
        $this->sid = $sid;

        return $this;
    }

    public function getSid(): string
    {
        return $this->sid;
    }

    public function toAsn1(): SequenceType
    {
        $this->controlValue = Asn1::octetString($this->sid);

        return parent::toAsn1();
    }
}
