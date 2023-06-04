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

namespace FreeDSx\Ldap\Protocol;

use Countable;
use FreeDSx\Ldap\LdapUrl;
use function count;
use function strtolower;

/**
 * Keeps track of referrals while they are being chased.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ReferralContext implements Countable
{
    /**
     * @var LdapUrl[]
     */
    private array $referrals;

    public function __construct(LdapUrl ...$referrals)
    {
        $this->referrals = $referrals;
    }

    /**
     * @return LdapUrl[]
     */
    public function getReferrals(): array
    {
        return $this->referrals;
    }

    public function addReferral(LdapUrl $referral): self
    {
        $this->referrals[] = $referral;

        return $this;
    }

    public function hasReferral(LdapUrl $url): bool
    {
        foreach ($this->referrals as $referral) {
            if (strtolower($referral->toString()) === strtolower($url->toString())) {
                return true;
            }
        }

        return false;
    }

    /**
     * @inheritDoc
     * @psalm-return 0|positive-int
     */
    public function count(): int
    {
        return count($this->referrals);
    }
}
