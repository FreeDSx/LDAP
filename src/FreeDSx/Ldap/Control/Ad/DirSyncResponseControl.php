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
 * Represents a DirSync Response. Defined in MS-ADTS 3.1.1.3.4.1.3. The control value response definition is:
 *
 * DirSyncResponseValue ::= SEQUENCE {
 *     MoreResults     INTEGER
 *     unused          INTEGER
 *     CookieServer    OCTET STRING
 * }
 *
 * @api
 *
 * @see https://msdn.microsoft.com/en-us/library/cc223347.aspx
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class DirSyncResponseControl extends Control
{
    public function __construct(
        private readonly int $moreResults,
        private readonly int $unused = 0,
        private readonly string $cookie = '',
    ) {
        parent::__construct(self::OID_DIR_SYNC);
    }

    public function getMoreResults(): int
    {
        return $this->moreResults;
    }

    public function hasMoreResults(): bool
    {
        return $this->moreResults !== 0;
    }

    public function getUnused(): int
    {
        return $this->unused;
    }

    public function getCookie(): string
    {
        return $this->cookie;
    }

    public function toAsn1(): SequenceType
    {
        $this->controlValue = Asn1::sequence(
            Asn1::integer($this->moreResults),
            Asn1::integer($this->unused),
            Asn1::octetString($this->cookie),
        );

        return parent::toAsn1();
    }
}
