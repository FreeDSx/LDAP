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

namespace FreeDSx\Ldap\Operation\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\IntegerType;

/**
 * RFC 4511, 4.11.
 *
 * AbandonRequest ::= [APPLICATION 16] MessageID
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class AbandonRequest implements RequestInterface
{
    protected const APP_TAG = 16;

    public function __construct(private int $messageID) {}

    public function setMessageId(int $messageID): self
    {
        $this->messageID = $messageID;

        return $this;
    }

    public function getMessageId(): int
    {
        return $this->messageID;
    }

    public function toAsn1(): IntegerType
    {
        return Asn1::application(
            self::APP_TAG,
            Asn1::integer($this->messageID),
        );
    }
}
