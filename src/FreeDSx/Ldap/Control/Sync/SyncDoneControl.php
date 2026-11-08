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
 * Represents a syncStateValue control. RFC 4533.
 *
 * syncDoneValue ::= SEQUENCE {
 *     cookie          syncCookie OPTIONAL,
 *     refreshDeletes  BOOLEAN DEFAULT FALSE
 * }
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com
 * @see https://tools.ietf.org/html/rfc4533
 */
class SyncDoneControl extends Control
{
    /**
     * RFC 4533 2.4 defines the control as non-critical, so the criticality is left at its default of FALSE.
     */
    public function __construct(
        private readonly ?string $cookie = null,
        private readonly bool $refreshDeletes = false,
    ) {
        parent::__construct(self::OID_SYNC_DONE);
    }

    public function getCookie(): ?string
    {
        return $this->cookie;
    }

    public function getRefreshDeletes(): bool
    {
        return $this->refreshDeletes;
    }

    public function toAsn1(): SequenceType
    {
        $this->controlValue = Asn1::sequence();
        if ($this->cookie !== null) {
            $this->controlValue->addChild(Asn1::octetString(
                $this->cookie,
            ));
        }
        // RFC 4511 5.1: a field holding its default value is absent from the encoding.
        if ($this->refreshDeletes) {
            $this->controlValue->addChild(Asn1::boolean(true));
        }

        return parent::toAsn1();
    }
}
