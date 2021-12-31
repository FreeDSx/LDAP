<?php

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
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Socket\Exception\ConnectionException;

/**
 * Logic for handling search operations.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientSearchHandler extends ClientBasicHandler
{
    /**
     * @param ClientProtocolContext $context
     * @return LdapMessageResponse|null
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
            $request->setBaseDn($context->getOptions()['base_dn'] ?? null);
        }

        return parent::handleRequest($context);
    }

    /**
     * @param LdapMessageRequest $messageTo
     * @param LdapMessageResponse $messageFrom
     * @param ClientQueue $queue
     * @param array $options
     * @return LdapMessageResponse|null
     * @throws OperationException
     * @throws BindException
     * @throws ProtocolException
     * @throws UnsolicitedNotificationException
     * @throws ConnectionException
     */
    public function handleResponse(LdapMessageRequest $messageTo, LdapMessageResponse $messageFrom, ClientQueue $queue, array $options): ?LdapMessageResponse
    {
        $entries = [];

        while (!($messageFrom->getResponse() instanceof SearchResultDone)) {
            $response = $messageFrom->getResponse();
            if ($response instanceof SearchResultEntry) {
                $entry = $response->getEntry();
                $entries[] = $entry;
            }
            $messageFrom = $queue->getMessage($messageTo->getMessageId());
        }

        $ldapResult = $messageFrom->getResponse();
        if (!$ldapResult instanceof LdapResult) {
            throw new OperationException('The final search result is malformed.');
        }

        $finalResponse = new LdapMessageResponse(
            $messageFrom->getMessageId(),
            new SearchResponse($ldapResult, new Entries(...$entries)),
            ...$messageFrom->controls()->toArray()
        );

        return parent::handleResponse($messageTo, $finalResponse, $queue, $options);
    }
}
