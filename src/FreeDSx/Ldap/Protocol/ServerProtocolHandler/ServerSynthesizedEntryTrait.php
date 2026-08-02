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

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;

/**
 * Shared reply path for handlers that synthesize their entry rather than reading it from storage.
 */
trait ServerSynthesizedEntryTrait
{
    /**
     * Whether the entry satisfies the request filter, per RFC 4511 section 4.5.1.
     *
     * Evaluate this against the whole entry, since selecting attributes must not change whether it matches.
     */
    private function matchesRequestFilter(
        LdapMessageRequest $message,
        Entry $entry,
        FilterEvaluatorInterface $filterEvaluator,
    ): bool {
        $request = $message->getRequest();

        if (!$request instanceof SearchRequest) {
            return true;
        }

        return $filterEvaluator->evaluate(
            $entry,
            $request->getFilter(),
        );
    }

    /**
     * Replies with the entry, or with an empty result when it is null.
     */
    private function replyWithEntry(
        LdapMessageRequest $message,
        ?Entry $entry,
    ): ResponseStream {
        $responses = $entry === null
            ? [new SearchResultDone(ResultCode::SUCCESS)]
            : [new SearchResultEntry($entry), new SearchResultDone(ResultCode::SUCCESS)];

        return ResponseStream::reply(
            $message,
            OperationOutcomeResult::succeeded(),
            ...$responses,
        );
    }
}
