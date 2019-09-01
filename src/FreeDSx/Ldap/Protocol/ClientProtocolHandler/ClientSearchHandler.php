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

use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\LdapQueue;

/**
 * Logic for handling search operations.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientSearchHandler extends ClientBasicHandler
{
    /**
     * {@inheritDoc}
     */
    public function handleRequest(LdapMessageRequest $message, LdapQueue $queue, array $options) : ?LdapMessageResponse
    {
        /** @var SearchRequest $request */
        $request = $message->getRequest();
        if ($request->getBaseDn() === null) {
            $request->setBaseDn($options['base_dn'] ?? null);
        }

        return parent::handleRequest($message, $queue, $options);
    }

    /**
     * {@inheritDoc}
     */
    public function handleResponse(LdapMessageRequest $messageTo, LdapMessageResponse $messageFrom, LdapQueue $queue, array $options): ?LdapMessageResponse
    {
        $entries = [];

        while(!($messageFrom->getResponse() instanceof SearchResultDone)) {
            $response = $messageFrom->getResponse();
            if ($response instanceof SearchResultEntry) {
                $entry = $response->getEntry();
                $entries[] = $entry;
            }
            $messageFrom = $queue->getMessage($messageTo->getMessageId());
        }

        $finalResponse = new LdapMessageResponse(
            $messageFrom->getMessageId(),
            new SearchResponse($messageFrom->getResponse(), new Entries(...$entries)),
            ...$messageFrom->controls()->toArray()
        );

        return parent::handleResponse($messageTo, $finalResponse, $queue, $options);
    }
}
