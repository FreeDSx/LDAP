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

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
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
use FreeDSx\Socket\Exception\ConnectionException;

/**
 * Logic for handling search operations.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientSearchHandler extends ClientBasicHandler
{
    /**
     * @throws EncoderException
     * @throws ProtocolException
     * @throws UnsolicitedNotificationException
     * @throws ConnectionException
     */
    public function handleRequest(ClientProtocolContext $context): ?LdapMessageResponse
    {
        /** @var SearchRequest $request */
        $request = $context->getRequest();
        if ($request->getBaseDn() === null) {
            $request->setBaseDn($context->getOptions()->getBaseDn() ?? null);
        }

        return parent::handleRequest($context);
    }

    /**
     * {@inheritDoc}
     * @throws OperationException
     * @throws BindException
     * @throws ProtocolException
     * @throws UnsolicitedNotificationException
     * @throws ConnectionException
     */
    public function handleResponse(
        LdapMessageRequest $messageTo,
        LdapMessageResponse $messageFrom,
        ClientQueue $queue,
        ClientOptions $options,
    ): ?LdapMessageResponse {
        $finalResponse = $this->search(
            $messageFrom,
            $messageTo,
            $queue,
        );

        return parent::handleResponse(
            $messageTo,
            $finalResponse,
            $queue,
            $options
        );
    }

    private function search(
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
