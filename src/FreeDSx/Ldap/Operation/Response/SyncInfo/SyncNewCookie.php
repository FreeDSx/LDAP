<?php

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
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Response\SyncInfoMessage;

/**
 * Represents a Sync Info Message syncCookie choice. RFC 4533.
 *
 *     newcookie      [0] syncCookie
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 * @see https://tools.ietf.org/html/rfc4533
 */
class SyncNewCookie extends SyncInfoMessage
{
    protected const VALUE_TAG = 0;

    /**
     * @param string $cookie
     */
    public function __construct(string $cookie)
    {
        parent::__construct($cookie);
    }

    /**
     *{@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $this->responseValue = Asn1::context(self::VALUE_TAG, Asn1::octetString($this->cookie));

        return parent::toAsn1();
    }

    /**
     *{@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        $cookie = self::decodeEncodedValue(
            $type,
            [
                AbstractType::TAG_CLASS_CONTEXT_SPECIFIC => [
                    self::VALUE_TAG => AbstractType::TAG_TYPE_OCTET_STRING
                ]
            ]
        );
        if (!$cookie instanceof OctetStringType) {
            throw new ProtocolException('The syncCookie must be an octet string.');
        }
        $syncNewCookie = new self($cookie->getValue());
        $syncNewCookie->responseName = self::decodeResponseName($type);

        return $syncNewCookie;
    }
}
