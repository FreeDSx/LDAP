<?php

declare(strict_types=1);

namespace spec\FreeDSx\Ldap;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Result\EntryResult;

trait TestFactoryTrait
{
    /**
     * @param Control[] $controls
     */
    protected static function makeSearchResponseFromEntries(
        Entries $entries = new Entries(),
        int $resultCode = ResultCode::SUCCESS,
        int $messageId = 1,
        string $dn = '',
        string $diagnostic = '',
        array $controls = [],
    ): LdapMessageResponse {
        $entryResults = [];

        foreach ($entries->toArray() as $i => $entry) {
            $entryResults[] = new EntryResult(new LdapMessageResponse(
                $i,
                new SearchResultEntry($entry)
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
            ),
            ...$controls,
        );
    }
}
