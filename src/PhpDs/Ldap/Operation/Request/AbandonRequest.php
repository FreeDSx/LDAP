<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpDs\Ldap\Operation\Request;

use PhpDs\Ldap\Asn1\Asn1;
use PhpDs\Ldap\Asn1\Type\AbstractType;

/**
 * RFC 4511, 4.11.
 *
 * AbandonRequest ::= [APPLICATION 16] MessageID
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class AbandonRequest implements RequestInterface
{
    protected const APP_TAG = 16;

    /**
     * @var int
     */
    protected $messageID;

    /**
     * @param int $messageID
     */
    public function __construct(int $messageID)
    {
        $this->messageID = $messageID;
    }

    /**
     * @param int $messageID
     * @return $this
     */
    public function setMessageId(int $messageID)
    {
        $this->messageID = $messageID;

        return $this;
    }

    /**
     * @return int
     */
    public function getMessageId() : int
    {
        return $this->messageID;
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        return new self($type->getValue());
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        return Asn1::application(self::APP_TAG, Asn1::integer($this->messageID));
    }
}
