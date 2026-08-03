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
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Applies read policy and the request filter to entries the server synthesizes rather than reads from storage.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class GeneratedEntryResponder
{
    public function __construct(
        private AccessControlInterface $accessControl,
        private FilterEvaluatorInterface $filterEvaluator,
    ) {}

    /**
     * Remove attributes the token may not read.
     *
     * Call this before matching, so a withheld attribute cannot satisfy the filter and disclose its value by the
     * entry coming back at all. Entry-level visibility is settled before a handler runs, so only attribute rules
     * apply here.
     */
    public function readable(
        Entry $entry,
        TokenInterface $token,
    ): Entry {
        return $this->accessControl->stripUnreadableAttributes(
            $token,
            $entry,
        );
    }

    /**
     * Whether the entry satisfies the request filter, per RFC 4511 section 4.5.1.
     *
     * Evaluate this against the whole entry, since selecting attributes must not change whether it matches.
     */
    public function matches(
        LdapMessageRequest $message,
        Entry $entry,
    ): bool {
        $request = $message->getRequest();

        if (!$request instanceof SearchRequest) {
            return true;
        }

        return $this->filterEvaluator->evaluate(
            $entry,
            $request->getFilter(),
        );
    }

    /**
     * Replies with the entry, or with an empty result when it is null.
     */
    public function reply(
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
