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

namespace FreeDSx\Ldap\Operation\Response\SyncInfo;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\SequenceType;

/**
 * @api
 */
trait SyncRefreshDoneTrait
{
    private bool $refreshDone;

    public function __construct(
        bool $refreshDone = true,
        ?string $cookie = null,
    ) {
        $this->refreshDone = $refreshDone;

        parent::__construct($cookie);
    }

    public function getRefreshDone(): bool
    {
        return $this->refreshDone;
    }

    public function toAsn1(): SequenceType
    {
        $asn1 = Asn1::context(
            static::valueTag(),
            Asn1::sequence(),
        );

        if ($this->cookie !== null) {
            $asn1->addChild(Asn1::octetString(
                $this->cookie,
            ));
        }

        // RFC 4511 5.1: a field holding its default value is absent, and this one defaults to TRUE.
        if (!$this->refreshDone) {
            $asn1->addChild(Asn1::boolean(false));
        }

        $this->setResponseValueToEncode($asn1);

        return parent::toAsn1();
    }

    abstract protected static function valueTag(): int;
}
