<?php

declare(strict_types=1);

namespace spec\FreeDSx\Ldap;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\Response\SearchResultReference;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Result\EntryResult;
use FreeDSx\Ldap\Search\Result\ReferralResult;

trait TestFactoryTrait
{
    /**
     * @param Control[] $controls
     * @param LdapUrl[] $referrals
     * @param SearchResultReference[] $searchReferralResults
     * @param SearchResultEntry[] $searchEntryResults
     */
    protected static function makeSearchResponseFromEntries(
        Entries $entries = new Entries(),
        int $resultCode = ResultCode::SUCCESS,
        int $messageId = 1,
        string $dn = '',
        string $diagnostic = '',
        array $controls = [],
        array $referrals = [],
        array $searchEntryResults = [],
        array $searchReferralResults = [],
    ): LdapMessageResponse {
        $entryResults = [];
        $referralResults = [];

        foreach ($entries->toArray() as $entry) {
            $entryResults[] = new EntryResult(new LdapMessageResponse(
                $messageId,
                new SearchResultEntry($entry),
            ));
        }
        foreach ($searchEntryResults as $entry) {
            $entryResults[] = new EntryResult(new LdapMessageResponse(
                $messageId,
                $entry
            ));
        }
        foreach ($referrals as $referral) {
            $referralResults[] = new ReferralResult(new LdapMessageResponse(
                $messageId,
                new SearchResultReference($referral),
            ));
        }
        foreach ($searchReferralResults as $referral) {
            $referralResults[] = new ReferralResult(new LdapMessageResponse(
                $messageId,
                $referral,
            ));
        }

        return new LdapMessageResponse(
            $messageId,
            new SearchResponse(
                new LdapResult(
                    $resultCode,
                    $dn,
                    $diagnostic,
                ),
                $entryResults,
                $referralResults,
            ),
            ...$controls,
        );
    }
}
