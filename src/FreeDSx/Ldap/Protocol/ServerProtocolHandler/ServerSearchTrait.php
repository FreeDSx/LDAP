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

use FreeDSx\Ldap\Entry\Entries;
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
        ServerQueue $queue
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
            new SearchResultDone(ResultCode::SUCCESS)
        );

        $queue->sendMessage(...$messages);
    }
}
