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

namespace FreeDSx\Ldap\Control\Sync;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;

/**
 * Represents a syncRequestValue control. RFC 4533.
 *
 * syncRequestValue ::= SEQUENCE {
 *     mode ENUMERATED {
 *         -- 0 unused
 *         refreshOnly       (1),
 *         -- 2 reserved
 *         refreshAndPersist (3)
 *     },
 *     cookie     syncCookie OPTIONAL,
 *     reloadHint BOOLEAN DEFAULT FALSE
 * }
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com
 * @see https://tools.ietf.org/html/rfc4533
 */
class SyncRequestControl extends Control
{
    public const MODE_REFRESH_ONLY = 1;

    public const MODE_REFRESH_AND_PERSIST = 3;

    public function __construct(
        private int $mode = self::MODE_REFRESH_ONLY,
        private ?string $cookie = null,
        private bool $reloadHint = false,
    ) {
        parent::__construct(
            self::OID_SYNC_REQUEST,
            true,
        );
    }

    public function getMode(): int
    {
        return $this->mode;
    }

    public function setMode(int $mode): self
    {
        $this->mode = $mode;

        return $this;
    }

    public function getCookie(): ?string
    {
        return $this->cookie;
    }

    public function setCookie(?string $cookie): self
    {
        $this->cookie = $cookie;

        return $this;
    }

    public function getReloadHint(): bool
    {
        return $this->reloadHint;
    }

    public function setReloadHint(bool $reloadHint): self
    {
        $this->reloadHint = $reloadHint;

        return $this;
    }

    public function toAsn1(): SequenceType
    {
        $this->controlValue = Asn1::sequence(Asn1::enumerated($this->mode));
        if ($this->cookie !== null) {
            $this->controlValue->addChild(Asn1::octetString($this->cookie));
        }

        // RFC 4511 5.1: a field holding its default value is absent from the encoding.
        if ($this->reloadHint) {
            $this->controlValue->addChild(Asn1::boolean(true));
        }

        return parent::toAsn1();
    }
}
