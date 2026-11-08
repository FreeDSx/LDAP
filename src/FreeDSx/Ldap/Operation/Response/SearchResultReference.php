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

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\LdapUrl;

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
     * @var array<int, LdapUrl>
     */
    private array $referrals;

    public function __construct(LdapUrl ...$referrals)
    {
        $this->referrals = array_values($referrals);
    }

    /**
     * @return array<int, LdapUrl>
     */
    public function getReferrals(): array
    {
        return $this->referrals;
    }

    public function toAsn1(): SequenceType
    {
        $referrals = [];
        foreach ($this->referrals as $referral) {
            $referrals[] = Asn1::octetString($referral->toString());
        }

        return Asn1::application(
            self::TAG_NUMBER,
            SequenceType::fromChildren($referrals),
        );
    }
}
