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
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\Response\SearchResultReference;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Search\Handler\EntryHandlerInterface;
use FreeDSx\Ldap\Search\Handler\ReferralHandlerInterface;
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
        /** @var SearchRequest $searchRequest */
        $searchRequest = $messageTo->getRequest();

        $entryHandler = $searchRequest->getEntryHandler();
        $referralHandler = $searchRequest->getReferralHandler();

        if ($entryHandler || $referralHandler) {
            $finalResponse = $this->searchWithHandlers(
                $messageFrom,
                $messageTo,
                $entryHandler,
                $referralHandler,
                $queue,
            );
        } else {
            $finalResponse = $this->searchWithoutHandlers(
                $messageFrom,
                $messageTo,
                $queue,
            );
        }

        return parent::handleResponse(
            $messageTo,
            $finalResponse,
            $queue,
            $options
        );
    }

    private function searchWithHandlers(
        LdapMessageResponse $messageFrom,
        LdapMessageRequest $messageTo,
        ?EntryHandlerInterface $entryHandler,
        ?ReferralHandlerInterface $referralHandler,
        ClientQueue $queue,
    ): LdapMessageResponse {
        while (!$messageFrom->getResponse() instanceof SearchResultDone) {
            $response = $messageFrom->getResponse();

            if ($response instanceof SearchResultEntry) {
                $entryHandler?->handleEntry(new EntryResult($messageFrom));
            } elseif ($response instanceof SearchResultReference) {
                $referralHandler?->handleReferral(new ReferralResult($messageFrom));
            }

            $messageFrom = $queue->getMessage($messageTo->getMessageId());
        }

        return $messageFrom;
    }

    private function searchWithoutHandlers(
        LdapMessageResponse $messageFrom,
        LdapMessageRequest $messageTo,
        ClientQueue $queue,
    ): LdapMessageResponse {
        $entryResults = [];
        $referralResults = [];

        while (!($messageFrom->getResponse() instanceof SearchResultDone)) {
            $response = $messageFrom->getResponse();

            if ($response instanceof SearchResultEntry) {
                $entryResults[] = new EntryResult($messageFrom);
            } elseif ($response instanceof SearchResultReference) {
                $referralResults[] = new ReferralResult($messageFrom);
            }

            $messageFrom = $queue->getMessage($messageTo->getMessageId());
        }

        $ldapResult = $messageFrom->getResponse();

        return new LdapMessageResponse(
            $messageFrom->getMessageId(),
            new SearchResponse(
                $ldapResult,
                $entryResults,
                $referralResults,
            ),
            ...$messageFrom->controls()
            ->toArray()
        );
    }
}
