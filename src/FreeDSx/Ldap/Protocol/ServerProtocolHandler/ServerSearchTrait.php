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
use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortingResponseControl;
use FreeDSx\Ldap\Control\SubentriesControl;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\Response\Cancellation;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Server\Subentry\SubentryVisibility;
use Generator;

trait ServerSearchTrait
{
    /**
     * Yields a SearchResultEntry per backend entry followed by the terminal SearchResultDone.
     * Yields nothing for abandoned requests; yields CANCELED + SUCCESS for cancelled requests.
     *
     * @return Generator<LdapMessageResponse>
     */
    private function buildResponseStream(
        SearchResult $searchResult,
        int $messageId,
        Cancellation $cancellation,
        Control ...$controls,
    ): Generator {
        $state = $searchResult->getState();

        foreach ($searchResult->getEntries() as $entry) {
            yield new LdapMessageResponse(
                $messageId,
                new SearchResultEntry($entry),
            );

            if ($cancellation->isSignalled()) {
                break;
            }
        }

        if ($cancellation->isAbandoned()) {
            return;
        }
        $cancelSignal = $cancellation->signal();

        if ($cancelSignal !== null && $cancellation->isCanceled()) {
            yield new LdapMessageResponse(
                $messageId,
                new SearchResultDone(
                    ResultCode::CANCELED,
                    $searchResult->getBaseDn(),
                ),
            );
            yield new LdapMessageResponse(
                $cancelSignal->getMessageId(),
                new ExtendedResponse(new LdapResult(ResultCode::SUCCESS)),
            );

            return;
        }

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
                get_class($request),
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
                ResultCode::PROTOCOL_ERROR,
            );
        }

        // The size is constrained to (0..maxInt), and a negative one would otherwise mean an unbounded page.
        if ($pagingControl->getSize() < 0) {
            throw new OperationException(
                'The paged results size must not be negative.',
                ResultCode::PROTOCOL_ERROR,
            );
        }

        return $pagingControl;
    }

    /**
     * @throws OperationException
     */
    private function assertBaseDnProvided(SearchRequest $request): Dn
    {
        $baseDn = $request->getBaseDn();

        if ($baseDn === null) {
            throw new OperationException(
                'No base DN provided.',
                ResultCode::PROTOCOL_ERROR,
            );
        }

        return $baseDn;
    }

    /**
     * Returns the stricter of the client-requested limit and the server maximum. Zero means no limit.
     */
    private function effectiveSizeLimit(
        int $requestLimit,
        int $serverMax,
    ): int {
        if ($serverMax === 0) {
            return $requestLimit;
        }

        if ($requestLimit === 0) {
            return $serverMax;
        }

        return min(
            $requestLimit,
            $serverMax,
        );
    }

    /**
     * Returns a ControlBag with server-consumed controls stripped; only paging is excluded (sort passes through to backends).
     */
    private function controlsForBackend(LdapMessageRequest $message): ControlBag
    {
        $filtered = array_filter(
            $message->controls()->toArray(),
            static fn(Control $control): bool => $control->getTypeOid() !== Control::OID_PAGING,
        );

        return new ControlBag(...$filtered);
    }

    private function subentryVisibility(ControlBag $controls): SubentryVisibility
    {
        $control = $controls->get(Control::OID_SUBENTRIES);

        return $control instanceof SubentriesControl && $control->getIsVisible()
            ? SubentryVisibility::Only
            : SubentryVisibility::Hide;
    }

    /**
     * Extracts the sorting control from the message, or returns null if absent.
     */
    private function sortingControl(LdapMessageRequest $message): ?SortingControl
    {
        $control = $message->controls()->get(Control::OID_SORTING);

        return $control instanceof SortingControl
            ? $control
            : null;
    }

    /**
     * The RFC 2891 sort response control, with the result code per §1.2 (first unsortable key wins).
     */
    private function sortingResponseControl(
        ?SortingControl $sortControl,
        Schema $schema,
    ): ?SortingResponseControl {
        if ($sortControl === null) {
            return null;
        }

        foreach ($sortControl->getSortKeys() as $sortKey) {
            $attribute = $sortKey->getAttribute();
            $attributeType = $schema->getAttributeType($attribute);

            if ($attributeType === null) {
                return new SortingResponseControl(
                    ResultCode::NO_SUCH_ATTRIBUTE,
                    $attribute,
                );
            }

            $orderingRule = $sortKey->getOrderingRule();
            $unknownRule = $orderingRule !== null
                && $schema->getMatchingRule($orderingRule) === null;

            if ($unknownRule || ($orderingRule === null && $attributeType->orderingOid === null)) {
                return new SortingResponseControl(
                    ResultCode::INAPPROPRIATE_MATCHING,
                    $attribute,
                );
            }
        }

        return new SortingResponseControl(ResultCode::SUCCESS);
    }
}
