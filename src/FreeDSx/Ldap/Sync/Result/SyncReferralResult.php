<?php

declare(strict_types=1);

namespace FreeDSx\Ldap\Sync\Result;

use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Result\ReferralResult;

class SyncReferralResult
{
    use SyncResultTrait;

    public function __construct(private readonly ReferralResult $referralResult)
    {}

    public function getMessage(): LdapMessageResponse
    {
        return $this->referralResult->getMessage();
    }

    /**
     * @return LdapUrl[]
     */
    public function getReferrals(): array
    {
        return $this->referralResult->getReferrals();
    }
}
