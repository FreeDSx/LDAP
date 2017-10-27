<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Operation\Response;

use FreeDSx\Ldap\Asn1\Asn1;
use FreeDSx\Ldap\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Operation\Referral;

/**
 * A search result reference. RFC 4511, 4.5.3.
 *
 * SearchResultReference ::= [APPLICATION 19] SEQUENCE
 *     SIZE (1..MAX) OF uri URI
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SearchResultReference implements ResponseInterface
{
    protected const TAG_NUMBER = 19;

    /**
     * @var Referral[]
     */
    protected $referrals;

    /**
     * @param Referral[] ...$referrals
     */
    public function __construct(Referral ...$referrals)
    {
        $this->referrals = $referrals;
    }

    /**
     * @return Referral[]
     */
    public function getReferrals() : array
    {
        return $this->referrals;
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        $referrals = [];

        /** @var \FreeDSx\Ldap\Asn1\Type\SequenceType $type */
        foreach ($type->getChildren() as $referral) {
            $referrals[] = new Referral($referral->getValue());
        }

        return new self(...$referrals);
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        return Asn1::application(self::TAG_NUMBER, Asn1::sequence(array_map(function ($ref) {
            return Asn1::ldapString($ref->toString);
        }, $this->referrals)));
    }
}
