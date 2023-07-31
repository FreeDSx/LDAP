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

namespace FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use Closure;
use FreeDSx\Ldap\Exception\CancelRequestException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
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
    private RequestCanceler $requestCanceler;

    private Closure $entryHandler;

    private Closure $referralHandler;

    private ?Closure $intermediateHandler = null;

    private bool $wasCancelHandled = false;

    private ?ExtendedResponse $canceledResponse = null;

    private function search(
        LdapMessageResponse $messageFrom,
        LdapMessageRequest $messageTo,
        ClientQueue $queue,
    ): LdapMessageResponse {
        /** @var SearchRequest $searchRequest */
        $searchRequest = $messageTo->getRequest();

        $cancelled = null;
        $entryResults = [];
        $referralResults = [];

        $this->requestCanceler = new RequestCanceler(
            queue: $queue,
            strategy: $searchRequest->getCancelStrategy(),
            messageProcessor: $this->processSearchMessage(...),
        );

        $this->entryHandler = $searchRequest->getEntryHandler() ??
            function (EntryResult $result) use (&$entryResults): void {
                $entryResults[] = $result;
            };
        $this->referralHandler = $searchRequest->getReferralHandler() ??
            function (ReferralResult $result) use (&$referralResults): void {
                $referralResults[] = $result;
            };
        $this->intermediateHandler = $searchRequest->getIntermediateResponseHandler();

        /** @var LdapResult $response */
        $response = $messageFrom->getResponse();
        while (!$response instanceof SearchResultDone) {
            try {
                $this->processSearchMessage($messageFrom);
            } catch (CancelRequestException) {
                break;
            }

            $messageFrom = $queue->getMessage($messageTo->getMessageId());
            /** @var LdapResult $response */
            $response = $messageFrom->getResponse();
        }

        // This is just to use less logic to account whether a handler was used / no search results were returned.
        // This just returns the search result done wrapped in a SearchResponse. The SearchResponse extends
        // SearchResultDone.
        return new LdapMessageResponse(
            $messageFrom->getMessageId(),
            new SearchResponse(
                $this->canceledResponse ?? $response,
                $entryResults,
                $referralResults,
            ),
            ...$messageFrom->controls()->toArray()
        );
    }

    private function processSearchMessage(LdapMessageResponse $messageFrom): void
    {
        $response = $messageFrom->getResponse();

        try {
            if ($response instanceof SearchResultEntry) {
                ($this->entryHandler)(new EntryResult($messageFrom));
            } elseif ($response instanceof SearchResultReference) {
                ($this->referralHandler)(new ReferralResult($messageFrom));
            } elseif ($response instanceof IntermediateResponse && $this->intermediateHandler) {
                ($this->intermediateHandler)($messageFrom);
            }
        } catch (CancelRequestException $cancelException) {
            // If the strategy is "continue", we only handle the first cancellation exception.
            // The entry handler may continue to throw it, but we will only send one cancel request.
            if (!$this->wasCancelHandled) {
                $this->wasCancelHandled = true;
                $this->canceledResponse = $this->requestCanceler->cancel($messageFrom->getMessageId());

                throw $cancelException;
            }
        }
    }
}
