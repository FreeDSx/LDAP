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
use FreeDSx\Asn1\Type\SequenceType;

/**
 * Represents a paged results control request value. RFC 2696.
 *
 * realSearchControlValue ::= SEQUENCE {
 *     size            INTEGER (0..maxInt),
 *                          -- requested page size from client
 *                          -- result set size estimate from server
 *     cookie          OCTET STRING }
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PagingControl extends Control
{
    public function __construct(
        private int $size,
        private string $cookie = '',
    ) {
        parent::__construct(self::OID_PAGING);
    }

    public function getCookie(): string
    {
        return $this->cookie;
    }

    public function getSize(): int
    {
        return $this->size;
    }

    public function setCookie(string $cookie): self
    {
        $this->cookie = $cookie;

        return $this;
    }

    public function setSize(int $size): self
    {
        $this->size = $size;

        return $this;
    }

    public function toAsn1(): SequenceType
    {
        $this->controlValue = Asn1::sequence(
            Asn1::integer($this->size),
            Asn1::octetString($this->cookie),
        );

        return parent::toAsn1();
    }
}
