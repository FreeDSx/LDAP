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
use FreeDSx\Ldap\Protocol\LdapMessage;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\Response\Cancellation;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Schema\Definition\MatchingRuleOid;
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
                new SearchResultDone(ResultCode::CANCELED),
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
                $searchResult->getMatchedDn(),
                $state->diagnosticMessage,
            ),
            ...$controls,
        );
    }

    /**
     * @throws OperationException
     */
    private function getSearchRequestFromMessage(LdapMessageRequest $message): SearchRequest
    {
        $request = $message->getRequest();

        if (!$request instanceof SearchRequest) {
            throw new RuntimeException(sprintf(
                'Expected a search request, but got %s.',
                get_class($request),
            ));
        }

        $this->assertSearchParametersInRange($request);
        $this->assertBaseDnParses($request);

        return $request;
    }

    /**
     * A base the DN grammar rejects would otherwise fall back to a lowercased string and read as a lookup miss,
     * reporting noSuchObject where RFC 4511 4.1.3 calls for invalidDNSyntax.
     *
     * @throws OperationException
     */
    private function assertBaseDnParses(SearchRequest $request): void
    {
        $baseDn = $request->getBaseDn();
        if ($baseDn === null || Dn::isValid($baseDn)) {
            return;
        }

        throw new OperationException(
            'The search base DN is not valid.',
            ResultCode::INVALID_DN_SYNTAX,
        );
    }

    /**
     * Rejects RFC 4511 4.5.1 field values the decoder admits but the ASN.1 constraints do not.
     *
     * The decoder checks each field's type and stops there, so an out-of-range value would otherwise be coerced
     * into a working request: an unknown scope reads as one level, and a negative sizeLimit defeats the server
     * maximum entirely.
     *
     * @throws OperationException
     */
    private function assertSearchParametersInRange(SearchRequest $request): void
    {
        // An unknown scope must not silently become a scope the client did not ask for.
        if (!in_array($request->getScope(), SearchRequest::SUPPORTED_SCOPES, true)) {
            throw new OperationException(
                'The search scope requested is not supported.',
                ResultCode::PROTOCOL_ERROR,
            );
        }

        if (!in_array($request->getDereferenceAliases(), SearchRequest::DEREF_VALUES, true)) {
            throw new OperationException(
                'The alias dereferencing value requested is not valid.',
                ResultCode::PROTOCOL_ERROR,
            );
        }

        $this->assertWithinMaxInt(
            $request->getSizeLimit(),
            'size limit',
        );
        $this->assertWithinMaxInt(
            $request->getTimeLimit(),
            'time limit',
        );
    }

    /**
     * @throws OperationException
     */
    private function assertWithinMaxInt(
        int $value,
        string $field,
    ): void {
        if ($value < 0 || $value > LdapMessage::MAX_INT) {
            throw new OperationException(
                sprintf('The %s requested is outside the permitted range.', $field),
                ResultCode::PROTOCOL_ERROR,
            );
        }
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
    private function effectiveLimit(
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
     * RFC 2891 §1.2: the sort response for a sort demanded critically that the server cannot honor.
     */
    private function unsatisfiedCriticalSort(
        ?SortingControl $sortControl,
        ?SortingResponseControl $sortResponse,
    ): ?SortingResponseControl {
        if ($sortControl === null || !$sortControl->getCriticality()) {
            return null;
        }

        if ($sortResponse === null || $sortResponse->getResult() === ResultCode::SUCCESS) {
            return null;
        }

        return $sortResponse;
    }

    /**
     * The refusal as an exception, for callers whose failure path already tears down per-request state.
     *
     * @throws OperationException
     */
    private function assertSortIsSatisfiable(
        ?SortingControl $sortControl,
        ?SortingResponseControl $sortResponse,
    ): void {
        if ($this->unsatisfiedCriticalSort($sortControl, $sortResponse) === null) {
            return;
        }

        throw new OperationException(
            'The requested sort could not be performed.',
            ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
        );
    }

    /**
     * RFC 2891 §1.2: a critical sort the server cannot honor fails the search and returns no entries.
     */
    private function refuseUnsortableCriticalSearch(
        LdapMessageRequest $message,
        ?SortingControl $sortControl,
        ?SortingResponseControl $sortResponse,
    ): ?ResponseStream {
        $unsatisfied = $this->unsatisfiedCriticalSort(
            $sortControl,
            $sortResponse,
        );
        if ($unsatisfied === null) {
            return null;
        }

        return ResponseStream::of(
            [new LdapMessageResponse(
                $message->getMessageId(),
                new SearchResultDone(
                    ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
                    diagnosticMessage: 'The requested sort could not be performed.',
                ),
                $unsatisfied,
            )],
            OperationOutcomeResult::failed(ResultCode::UNAVAILABLE_CRITICAL_EXTENSION),
        );
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

        $seen = [];

        foreach ($sortControl->getSortKeys() as $sortKey) {
            $attribute = $sortKey->getAttribute();
            $attributeType = $schema->getAttributeType($attribute);

            // RFC 2891 §1.1: an attribute type should occur in the key list only once.
            if (isset($seen[strtolower($attribute)])) {
                return new SortingResponseControl(
                    ResultCode::UNWILLING_TO_PERFORM,
                    $attribute,
                );
            }
            $seen[strtolower($attribute)] = true;

            if ($attributeType === null) {
                return new SortingResponseControl(
                    ResultCode::NO_SUCH_ATTRIBUTE,
                    $attribute,
                );
            }

            // A rule the stored order cannot provide must not be reported as success (RFC 2891 §2). Naming no rule
            // asks only for the server's own order on that attribute, which it always has.
            $orderingRule = $sortKey->getOrderingRule();
            if ($orderingRule !== null && !$this->ordersByRule($schema, $attribute, $orderingRule)) {
                return new SortingResponseControl(
                    ResultCode::INAPPROPRIATE_MATCHING,
                    $attribute,
                );
            }
        }

        return new SortingResponseControl(ResultCode::SUCCESS);
    }

    /**
     * Whether the order the store keeps for the attribute is the one this rule names.
     */
    private function ordersByRule(
        Schema $schema,
        string $attribute,
        string $orderingRule,
    ): bool {
        $rule = $schema->getMatchingRule($orderingRule);
        if ($rule === null) {
            return false;
        }

        // Values compare as numbers whatever form the key holds
        if ($rule->oid === MatchingRuleOid::OID_INTEGER_ORDERING_MATCH) {
            return true;
        }

        $equalityOid = $schema->getEqualityRuleOid($attribute);
        if ($equalityOid !== null && $schema->getComparator($rule->oid) === $schema->getComparator($equalityOid)) {
            return true;
        }

        return $rule->oid === MatchingRuleOid::OID_CASE_IGNORE_ORDERING_MATCH
            && $schema->isCaseInsensitiveMatched($attribute) === true;
    }
}
