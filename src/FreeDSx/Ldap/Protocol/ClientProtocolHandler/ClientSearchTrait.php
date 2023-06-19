<?php

declare(strict_types=1);

namespace FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\IntermediateResponse;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\Response\SearchResultReference;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Search\Result\EntryResult;
use FreeDSx\Ldap\Search\Result\ReferralResult;

trait ClientSearchTrait
{
    private static function search(
        LdapMessageResponse $messageFrom,
        LdapMessageRequest  $messageTo,
        ClientQueue $queue,
    ): LdapMessageResponse {
        /** @var SearchRequest $searchRequest */
        $searchRequest = $messageTo->getRequest();

        $entryResults = [];
        $referralResults = [];

        $entryHandler = $searchRequest->getEntryHandler() ??
            function(EntryResult $result) use (&$entryResults): void {
                $entryResults[] = $result;
            };
        $referralHandler = $searchRequest->getReferralHandler() ??
            function(ReferralResult $result) use (&$referralResults): void {
                $referralResults[] = $result;
            };
        $intermediateHandler = $searchRequest->getIntermediateResponseHandler();

        while (!$messageFrom->getResponse() instanceof SearchResultDone) {
            $response = $messageFrom->getResponse();

            if ($response instanceof SearchResultEntry) {
                $entryHandler(new EntryResult($messageFrom));
            } elseif ($response instanceof SearchResultReference) {
                $referralHandler(new ReferralResult($messageFrom));
            } elseif ($response instanceof IntermediateResponse && $intermediateHandler) {
                $intermediateHandler($messageFrom);
            }

            $messageFrom = $queue->getMessage($messageTo->getMessageId());
        }

        // This is just to use less logic to account whether a handler was used / no search results were returned.
        // This just returns the search result done wrapped in a SearchResponse. The SearchResponse extends
        // SearchResultDone.
        return new LdapMessageResponse(
            $messageFrom->getMessageId(),
            new SearchResponse(
                $messageFrom->getResponse(),
                $entryResults,
                $referralResults,
            ),
            ...$messageFrom->controls()
            ->toArray()
        );
    }
}
