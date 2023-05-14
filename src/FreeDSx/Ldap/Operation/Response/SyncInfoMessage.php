<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Operation\Response;


use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncIdSet;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncNewCookie;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncRefreshDelete;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncRefreshPresent;

/**
 * Represents a Sync Info Message, which is an Intermediate Response Message. RFC 4533.
 *
 * syncInfoValue ::= CHOICE {
 *     newcookie      [0] syncCookie,
 *     refreshDelete  [1] SEQUENCE {
 *         cookie         syncCookie OPTIONAL,
 *         refreshDone    BOOLEAN DEFAULT TRUE
 *     },
 *     refreshPresent [2] SEQUENCE {
 *         cookie         syncCookie OPTIONAL,
 *         refreshDone    BOOLEAN DEFAULT TRUE
 *     },
 *     syncIdSet      [3] SEQUENCE {
 *         cookie         syncCookie OPTIONAL,
 *         refreshDeletes BOOLEAN DEFAULT FALSE,
 *         syncUUIDs      SET OF syncUUID
 *     }
 * }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 * @see https://tools.ietf.org/html/rfc4533
 */
abstract class SyncInfoMessage extends IntermediateResponse
{
    /**
     * @var null|string
     */
    protected $cookie;

    /**
     * @param string|null $cookie
     */
    public function __construct(?string $cookie = null)
    {
        $this->cookie = $cookie;
        parent::__construct(self::OID_SYNC_INFO, null);
    }

    /**
     * @return string|null
     */
    public function getCookie(): ?string
    {
        return $this->cookie;
    }

    /**
     * {@inheritDoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        $value = $type->getChild(1);
        if ($value === null) {
            throw new ProtocolException('The SyncInfoMessage must have a value.');
        }

        switch ($value->getTagNumber()) {
            case 0:
                return SyncNewCookie::fromAsn1($type);
            case 1:
                return SyncRefreshDelete::fromAsn1($type);
            case 2:
                return SyncRefreshPresent::fromAsn1($type);
            case 3:
                return SyncIdSet::fromAsn1($type);
            default:
                throw new ProtocolException(sprintf('The tag number %s for a SyncInfoMessage was unexpected.', $value->getTagNumber()));
        }
    }
}
