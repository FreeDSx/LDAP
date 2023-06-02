<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Exception;

use Exception;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\ResultCode;

/**
 * Represents a referral exception from an operation that needs to be chased to be completed.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ReferralException extends Exception
{
    /**
     * @var LdapUrl[]
     */
    private array $referrals;

    public function __construct(
        string $diagnostic,
        LdapUrl ...$referrals
    ) {
        $this->referrals = $referrals;
        parent::__construct(
            $diagnostic,
            ResultCode::REFERRAL
        );
    }

    /**
     * @return LdapUrl[]
     */
    public function getReferrals(): array
    {
        return $this->referrals;
    }
}
