<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Control\Ad;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\ProtocolException;

/**
 * Represents a DirSync Response. Defined in MS-ADTS 3.1.1.3.4.1.3. The control value response definition is:
 *
 * DirSyncResponseValue ::= SEQUENCE {
 *     MoreResults     INTEGER
 *     unused          INTEGER
 *     CookieServer    OCTET STRING
 * }
 *
 * @see https://msdn.microsoft.com/en-us/library/cc223347.aspx
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class DirSyncResponseControl extends Control
{
    /**
     * @var int
     */
    protected $moreResults;

    /**
     * @var int
     */
    protected $unused;

    /**
     * @var string
     */
    protected $cookie;

    /**
     * @param int $moreResults
     * @param int $unused
     * @param string $cookie
     */
    public function __construct(int $moreResults, int $unused = 0, string $cookie = '')
    {
        $this->moreResults = $moreResults;
        $this->unused = $unused;
        $this->cookie = $cookie;
        parent::__construct(self::OID_DIR_SYNC);
    }

    /**
     * @return int
     */
    public function getMoreResults(): int
    {
        return $this->moreResults;
    }

    /**
     * @return bool
     */
    public function hasMoreResults(): bool
    {
        return $this->moreResults !== 0;
    }

    /**
     * @return int
     */
    public function getUnused(): int
    {
        return $this->unused;
    }

    /**
     * @return string
     */
    public function getCookie(): string
    {
        return $this->cookie;
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        $response = self::decodeEncodedValue($type);
        if (!$response instanceof SequenceType) {
            throw new ProtocolException('A DirSyncResponse control value must be a sequence type with 3 children.');
        }
        $more = $response->getChild(0);
        $unused = $response->getChild(1);
        $cookie = $response->getChild(2);
        if (!$more instanceof IntegerType) {
            throw new ProtocolException('A DirSyncResponse control value sequence 0 must be an integer type.');
        }
        if (!$unused instanceof IntegerType) {
            throw new ProtocolException('A DirSyncResponse control value sequence 1 must be an integer type.');
        }
        if (!$cookie instanceof OctetStringType) {
            throw new ProtocolException('A DirSyncResponse control value sequence 2 must be an octet string type.');
        }

        /** @var SequenceType $request */
        $control = new self(
            $more->getValue(),
            $unused->getValue(),
            $cookie->getValue()
        );

        return self::mergeControlData($control, $type);
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $this->controlValue = Asn1::sequence(
            Asn1::integer($this->moreResults),
            Asn1::integer($this->unused),
            Asn1::octetString($this->cookie)
        );

        return parent::toAsn1();
    }
}
