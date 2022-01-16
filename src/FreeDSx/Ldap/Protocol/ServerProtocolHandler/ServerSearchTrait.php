<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;

trait ServerSearchTrait
{
    /**
     * @param Entries $entries
     * @param LdapMessageRequest $message
     * @param ServerQueue $queue
     * @return void
     */
    private function sendEntriesToClient(
        Entries $entries,
        LdapMessageRequest $message,
        ServerQueue $queue,
        Control ...$controls
    ): void {
        $messages = [];

        foreach ($entries->toArray() as $entry) {
            $messages[] = new LdapMessageResponse(
                $message->getMessageId(),
                new SearchResultEntry($entry)
            );
        }

        $messages[] = new LdapMessageResponse(
            $message->getMessageId(),
            new SearchResultDone(ResultCode::SUCCESS),
            ...$controls
        );

        $queue->sendMessage(...$messages);
    }

    /**
     * @param LdapMessageRequest $message
     * @return SearchRequest
     */
    private function getSearchRequestFromMessage(LdapMessageRequest $message): SearchRequest
    {
        $request = $message->getRequest();

        if (!$request instanceof SearchRequest) {
            throw new RuntimeException(sprintf(
                'Expected a search request, but got %s.',
                get_class($request)
            ));
        }
        return $request;
    }

    /**
     * @param LdapMessageRequest $message
     * @return PagingControl
     * @throws OperationException
     */
    private function getPagingControlFromMessage(LdapMessageRequest $message): PagingControl
    {
        $pagingControl = $message->controls()->get(Control::OID_PAGING);

        if (!$pagingControl instanceof PagingControl) {
            throw new OperationException(
                'The paging control was expected, but not received.',
                ResultCode::PROTOCOL_ERROR
            );
        }

        return $pagingControl;
    }
}
