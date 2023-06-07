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
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\BooleanType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Asn1\Type\SetType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Response\IntermediateResponse;
use FreeDSx\Ldap\Operation\Response\SyncInfoMessage;
use function count;

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

    private array $entryUuids;

    /**
     * @param string[] $entryUuids
     */
    public function __construct(
        array $entryUuids,
        bool $refreshDeletes = false,
        ?string $cookie = null
    ) {
        $this->entryUuids = $entryUuids;
        $this->refreshDeletes = $refreshDeletes;

        parent::__construct($cookie);
    }

    public function getRefreshDeletes() : ?bool
    {
        return $this->refreshDeletes;
    }

    /**
     * @return string[]
     */
    public function getEntryUuids() : array
    {
        return $this->entryUuids;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $asn1 = Asn1::context(
            self::VALUE_TAG,
            Asn1::sequence()
        );

        if ($this->cookie !== null) {
            $asn1->addChild(Asn1::octetString(
                $this->cookie
            ));
        }

        $uuids = [];
        foreach ($this->entryUuids as $uuid) {
            $uuids[] = Asn1::octetString($uuid);
        }
        $asn1->addChild(
            Asn1::boolean($this->refreshDeletes),
            Asn1::setOf(...$uuids)
        );

        $this->setResponseValueToEncode($asn1);

        return parent::toAsn1();
    }

    /**
     *{@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type): IntermediateResponse
    {
        $responseName = self::decodeResponseName($type);
        if ($responseName !== self::OID_SYNC_INFO) {
            throw new ProtocolException(sprintf(
                'The response name should be "%s", but was "%s".',
                self::OID_SYNC_INFO,
                $responseName
            ));
        }

        $responseValue = self::decodeEncodedValue(
            $type,
            [
                AbstractType::TAG_CLASS_CONTEXT_SPECIFIC => [
                    self::VALUE_TAG => AbstractType::TAG_TYPE_SEQUENCE
                ]
            ]
        );
        if (!$responseValue instanceof SequenceType || count($type->getChildren()) >= 3) {
            throw new ProtocolException(
                'Expected a sequence type with 2 or less children for a refreshPresent.'
            );
        }

        $cookie = null;
        $refreshDeletes = false;
        $entryUuids = null;
        foreach ($responseValue->getChildren() as $child) {
            if ($child instanceof OctetStringType) {
                $cookie = $child->getValue();
            } elseif ($child instanceof BooleanType) {
                $refreshDeletes = $child->getValue();
            } elseif ($child instanceof SetType) {
                $entryUuids = [];
                foreach ($child->getChildren() as $entryUuid) {
                    if (!$entryUuid instanceof OctetStringType) {
                        throw new ProtocolException('The entryUuid needs to be an octet string type.');
                    }
                    $entryUuids[] = $entryUuid->getValue();
                }
            } else {
                throw new ProtocolException('Unexpected value in the syncIdSet response.');
            }
        }

        if ($entryUuids === null) {
            throw new ProtocolException('Expected a set of entryUuids, but received none.');
        }

        return new self(
            $entryUuids,
            $refreshDeletes,
            $cookie,
        );
    }
}
