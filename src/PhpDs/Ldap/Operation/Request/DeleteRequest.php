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
use PhpDs\Ldap\Asn1\Type\OctetStringType;
use PhpDs\Ldap\Entry\Dn;
use PhpDs\Ldap\Exception\ProtocolException;

/**
 * RFC 4511, 4.8
 *
 * DelRequest ::= [APPLICATION 10] LDAPDN
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class DeleteRequest implements RequestInterface
{
    protected const APP_TAG = 10;

    /**
     * @var Dn
     */
    protected $dn;

    /**
     * @param string $dn
     */
    public function __construct($dn)
    {
        $this->dn = $dn instanceof Dn ? $dn : new Dn($dn);
    }

    /**
     * @param string $dn
     * @return $this
     */
    public function setDn($dn)
    {
        $this->dn = $dn instanceof Dn ? $dn : new Dn($dn);

        return $this;
    }

    /**
     * @return Dn
     */
    public function getDn() : Dn
    {
        return $this->dn;
    }

    public function toAsn1(): AbstractType
    {
        return Asn1::application(self::APP_TAG, Asn1::ldapDn($this->dn->toString()));
    }

    public static function fromAsn1(AbstractType $type)
    {
        self::validate($type);

        return new self($type->getValue());
    }

    /**
     * @param AbstractType $type
     * @throws ProtocolException
     */
    protected static function validate(AbstractType $type) : void
    {
        if (!$type instanceof OctetStringType || $type->getTagClass() !== AbstractType::TAG_CLASS_APPLICATION) {
            throw new ProtocolException('The delete request must be an octet string with an application tag class.');
        }
        if ($type->getTagNumber() !== self::APP_TAG) {
            throw new ProtocolException(sprintf(
                'The delete request must have an app tag of %s, received: %s',
                self::APP_TAG,
                $type->getTagNumber()
            ));
        }
    }
}
