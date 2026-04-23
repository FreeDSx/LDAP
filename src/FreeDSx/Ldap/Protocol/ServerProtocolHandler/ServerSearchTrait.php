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

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use Generator;

trait ServerSearchTrait
{
    private function sendEntriesToClient(
        SearchResult $searchResult,
        LdapMessageRequest $message,
        ServerQueue $queue,
        Control ...$controls
    ): void {
        $queue->sendMessages($this->buildResponseStream(
            $searchResult,
            $message->getMessageId(),
            ...$controls,
        ));
    }

    /**
     * Yields a SearchResultEntry per backend entry followed by the terminal SearchResultDone.
     *
     * @return Generator<LdapMessageResponse>
     */
    private function buildResponseStream(
        SearchResult $searchResult,
        int $messageId,
        Control ...$controls,
    ): Generator {
        foreach ($searchResult->getEntries() as $entry) {
            yield new LdapMessageResponse(
                $messageId,
                new SearchResultEntry($entry),
            );
        }

        $state = $searchResult->getState();

        yield new LdapMessageResponse(
            $messageId,
            new SearchResultDone(
                $state->resultCode,
                $searchResult->getBaseDn(),
                $state->diagnosticMessage,
            ),
            ...$controls,
        );
    }

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

    /**
     * @throws OperationException
     */
    private function assertBaseDnProvided(SearchRequest $request): void
    {
        if ($request->getBaseDn() === null) {
            throw new OperationException(
                'No base DN provided.',
                ResultCode::PROTOCOL_ERROR,
            );
        }
    }

    /**
     * Returns a ControlBag containing the message controls minus the paging control,
     * which the server consumes itself and must not forward to backends.
     */
    private function nonPagingControls(LdapMessageRequest $message): ControlBag
    {
        $filtered = array_filter(
            $message->controls()->toArray(),
            static fn (Control $control): bool => $control->getTypeOid() !== Control::OID_PAGING,
        );

        return new ControlBag(...$filtered);
    }

    /**
     * Filter the attributes on an entry according to the requested attribute list.
     *
     * An empty list means return all attributes. The special value "*" also means
     * all attributes. "1.1" means return no attributes (just the DN).
     *
     * @param Attribute[] $requestedAttrs
     */
    private function applyAttributeFilter(
        Entry $entry,
        array $requestedAttrs,
        bool $typesOnly,
    ): Entry {
        $names = array_map(
            static fn(Attribute $a): string => strtolower($a->getDescription()),
            $requestedAttrs
        );

        $returnAll = count($names) === 0 || in_array('*', $names, true);
        $returnNone = count($names) === 1 && $names[0] === '1.1';

        $filteredAttributes = [];

        foreach ($entry->getAttributes() as $attribute) {
            if ($returnNone) {
                break;
            }

            if (!$returnAll && !in_array(strtolower($attribute->getDescription()), $names, true)) {
                continue;
            }

            if ($typesOnly) {
                $filteredAttributes[] = new Attribute($attribute->getName());
            } else {
                $filteredAttributes[] = $attribute;
            }
        }

        return new Entry(
            $entry->getDn(),
            ...$filteredAttributes
        );
    }
}
