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
use FreeDSx\Asn1\Type\SetOfType;
use FreeDSx\Ldap\Operation\Response\SyncInfoMessage;

/**
 * Represents a Sync Info Message syncIdSet choice. RFC 4533.
 *
 *     syncIdSet      [3] SEQUENCE {
 *         cookie         syncCookie OPTIONAL,
 *         refreshDeletes BOOLEAN DEFAULT FALSE,
 *         syncUUIDs      SET OF syncUUID
 *     }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 * @see https://tools.ietf.org/html/rfc4533
 */
class SyncIdSet extends SyncInfoMessage
{
    protected const VALUE_TAG = 3;

    private bool $refreshDeletes;

    /**
     * @var string[]
     */
    private array $entryUuids;

    /**
     * @param string[] $entryUuids
     */
    public function __construct(
        array $entryUuids,
        bool $refreshDeletes = false,
        ?string $cookie = null,
    ) {
        $this->entryUuids = $entryUuids;
        $this->refreshDeletes = $refreshDeletes;

        parent::__construct($cookie);
    }

    public function getRefreshDeletes(): ?bool
    {
        return $this->refreshDeletes;
    }

    /**
     * @return string[]
     */
    public function getEntryUuids(): array
    {
        return $this->entryUuids;
    }

    public function toAsn1(): SequenceType
    {
        $asn1 = Asn1::context(
            self::VALUE_TAG,
            Asn1::sequence(),
        );

        if ($this->cookie !== null) {
            $asn1->addChild(Asn1::octetString(
                $this->cookie,
            ));
        }

        $uuids = [];
        foreach ($this->entryUuids as $uuid) {
            $uuids[] = Asn1::octetString($uuid);
        }
        // RFC 4511 5.1: a field holding its default value is absent from the encoding.
        if ($this->refreshDeletes) {
            $asn1->addChild(Asn1::boolean(true));
        }

        $asn1->addChild(SetOfType::fromChildren($uuids));

        $this->setResponseValueToEncode($asn1);

        return parent::toAsn1();
    }
}
