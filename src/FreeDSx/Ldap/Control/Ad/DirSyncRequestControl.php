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
 * Represents a DirSync Request. Defined in MS-ADTS 3.1.1.3.4.1.3. The control value request definition is:
 *
 *  DirSyncRequestValue ::= SEQUENCE {
 *      Flags       INTEGER
 *      MaxBytes    INTEGER
 *      Cookie      OCTET STRING
 *  }
 *
 * @api
 *
 * @see https://msdn.microsoft.com/en-us/library/cc223347.aspx
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class DirSyncRequestControl extends Control
{
    /**
     * If this flag is present, the client can only view objects and attributes that are otherwise accessible to the client.
     * If this flag is not present, the server checks if the client has access rights to read the changes in the NC.
     */
    public const FLAG_OBJECT_SECURITY = 0x00000001;

    /**
     * The server returns parent objects before child objects.
     */
    public const FLAG_ANCESTORS_FIRST_ORDER = 0x00000800;

    /**
     * This flag can optionally be passed to the DC, but it has no effect.
     */
    public const FLAG_PUBLIC_DATA_ONLY = 0x00002000;

    /**
     * If this flag is not present, all of the values, up to a server-specified limit, in a multivalued attribute are
     * returned when any value changes. If this flag is present, only the changed values are returned, provided the
     * attribute is a forward link value.
     *
     * Note: This flag needs to be encoded as a negative, due to how AD interprets the flags value.
     */
    public const FLAG_INCREMENTAL_VALUES = -0x80000000;

    public function __construct(
        private int $flags = self::FLAG_INCREMENTAL_VALUES,
        private string $cookie = '',
        private int $maxBytes = 2147483647,
    ) {
        parent::__construct(
            self::OID_DIR_SYNC,
            true,
        );
    }

    public function getFlags(): int
    {
        return $this->flags;
    }

    public function setFlags(int $flags): self
    {
        $this->flags = $flags;

        return $this;
    }

    public function getMaxBytes(): int
    {
        return $this->maxBytes;
    }

    public function setMaxBytes(int $maxBytes): self
    {
        $this->maxBytes = $maxBytes;

        return $this;
    }

    public function getCookie(): string
    {
        return $this->cookie;
    }

    public function setCookie(string $cookie): self
    {
        $this->cookie = $cookie;

        return $this;
    }

    public function toAsn1(): SequenceType
    {
        $this->controlValue = Asn1::sequence(
            Asn1::integer($this->flags),
            Asn1::integer($this->maxBytes),
            Asn1::octetString($this->cookie),
        );

        return parent::toAsn1();
    }
}
