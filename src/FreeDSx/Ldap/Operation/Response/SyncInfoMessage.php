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

namespace FreeDSx\Ldap\Operation\Response;

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
    public function __construct(protected ?string $cookie = null)
    {
        parent::__construct(
            self::OID_SYNC_INFO,
            null,
        );
    }

    public function getCookie(): ?string
    {
        return $this->cookie;
    }
}
