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

use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Control\Sorting\SortingResponseControl;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\Budget\HeldResponse;
use FreeDSx\Ldap\Protocol\Queue\Response\Cancellation;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Server\AccessControl\MatchedDnFilter;
use FreeDSx\Ldap\Server\Paging\CollectedPage;
use FreeDSx\Ldap\Server\Paging\PageFiller;
use FreeDSx\Ldap\Server\Paging\PagingRequest;
use FreeDSx\Ldap\Server\Paging\PagingResponse;
use FreeDSx\Ldap\Server\Paging\PagingSession;
use FreeDSx\Ldap\Server\Paging\PagingSessionTracker;
use FreeDSx\Ldap\Server\Operation\SearchOperationResult;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use Generator;

/**
 * Handles paged searches, resuming each from the session it left unfinished on the connection.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerPagingHandler implements ServerProtocolHandlerInterface
{
    use ServerSearchTrait;

    public function __construct(
        private readonly MatchedDnFilter $matchedDnFilter,
        private readonly PagingSessionTracker $sessions,
        private readonly Schema $schema,
        private readonly PageFiller $pageFiller,
    ) {}

    /**
     * @inheritDoc
     * @throws ProtocolException
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): ResponseStream {
        $sortControl = $this->sortingControl($message);
        $sortResponse = $this->sortingResponseControl(
            $sortControl,
            $this->schema,
        );
        $pagingRequest = $this->makePagingRequest(
            $message,
            $sortResponse,
        );
        $session = $this->sessions->find($pagingRequest);
        $searchRequest = $pagingRequest->getSearchRequest();

        $response = null;
        $collected = null;
        $controls = [];
        $entriesReturned = 0;
        $failure = null;
        try {
            $this->assertBaseDnProvided($searchRequest);
            $this->assertSortIsSatisfiable(
                $sortControl,
                $sortResponse,
            );

            $collected = $this->collectPage(
                $pagingRequest,
                $session,
                $token,
            );
            $response = $collected === null
                ? PagingResponse::makeFinal(new Entries())
                : $this->buildPagingResponse(
                    $collected,
                    $pagingRequest,
                    $session,
                );
            if ($response->isSizeLimitExceeded()) {
                $searchResult = SearchResult::makeSizeLimitResult($response->getEntries());
                $controls[] = new PagingControl(0, '');
            } else {
                $searchResult = SearchResult::makeSuccessResult($response->getEntries());
                $controls[] = new PagingControl(
                    $response->getRemaining(),
                    $response->getCookie(),
                );
            }
            $entriesReturned = $response->getEntries()->count();
        } catch (OperationException $e) {
            $failure = $e;
            $matchedDn = $this->matchedDnFilter->filter(
                $e->getMatchedDn(),
                $token,
            );
            $searchResult = SearchResult::makeErrorResult(
                $e->getCode(),
                $matchedDn !== null
                    ? $matchedDn->toString()
                    : '',
                $e->getMessage(),
            );
            $controls[] = new PagingControl(
                0,
                $this->cookieAfterFailure(
                    $e,
                    $session,
                ),
            );
        }

        if ($sortResponse !== null) {
            $controls[] = $sortResponse;
        }

        /**
         * Per Section 3 of RFC 2696:
         *
         *     If, for any reason, the server cannot resume a paged search operation
         *     for a client, then it SHOULD return the appropriate error in a
         *     searchResultDone entry. If this occurs, both client and server should
         *     assume the paged result set is closed and no longer resumable.
         *
         * If a search result is anything other than success, or the paging is complete, end the session it resumed.
         * A page refused as busy keeps it for the same cookie to be sent again once the server has room.
         */
        $resultCode = $searchResult->getState()->resultCode;
        $isClosed = ($response && $response->isComplete())
            || ($resultCode !== ResultCode::SUCCESS && $resultCode !== ResultCode::BUSY);
        if ($session !== null && $isClosed) {
            $this->sessions->end($session);
        }

        $outcome = $failure !== null
            ? SearchOperationResult::failure(
                $message,
                $failure,
            )
            : SearchOperationResult::success(
                $message,
                $entriesReturned,
            );

        // A page is pre-collected and bounded, so it is bulk-sent without mid-page cancel polling.
        return ResponseStream::of(
            $this->heldUntilWritten(
                $this->buildResponseStream(
                    $searchResult,
                    $message->getMessageId(),
                    new Cancellation(),
                    ...$controls,
                ),
                $collected?->held,
            ),
            $outcome,
        );
    }

    /**
     * Keeps what the page holds counted until the writer has taken the page's last message.
     *
     * @param Generator<LdapMessageResponse> $stream
     * @return Generator<LdapMessageResponse>
     */
    private function heldUntilWritten(
        Generator $stream,
        ?HeldResponse $held,
    ): Generator {
        yield from $stream;

        unset($held);
    }

    /**
     * The cookie a failed page returns, which is its kept session's own when the page was only refused as busy.
     */
    private function cookieAfterFailure(
        OperationException $failure,
        ?PagingSession $session,
    ): string {
        if ($session === null || $failure->getCode() !== ResultCode::BUSY) {
            return '';
        }

        return $session->nextCookie();
    }

    /**
     * The page the request asks for, or null when it gives up its paged search.
     *
     * @throws OperationException
     * @throws ProtocolException
     */
    private function collectPage(
        PagingRequest $pagingRequest,
        ?PagingSession $session,
        TokenInterface $token,
    ): ?CollectedPage {
        if ($session === null) {
            return $this->pageFiller->fill(
                $pagingRequest,
                $token,
                null,
            );
        }
        $this->sessions->assertSameSearch(
            $pagingRequest,
            $session,
        );

        if ($pagingRequest->isAbandonRequest()) {
            return null;
        }

        // The page is filled from the request just received, which a matching fingerprint vouches for.
        return $this->pageFiller->fill(
            $pagingRequest,
            $token,
            $session->cursor(),
        );
    }

    /**
     * @throws OperationException
     * @throws ProtocolException
     */
    private function buildPagingResponse(
        CollectedPage $collected,
        PagingRequest $pagingRequest,
        ?PagingSession $session,
    ): PagingResponse {
        $entries = new Entries(...$collected->entries);

        if ($collected->isSizeLimitExceeded) {
            return PagingResponse::makeSizeLimitExceeded($entries);
        }

        // Without a position there is nothing to resume from, so the result has to be treated as finished.
        if ($collected->isResultExhausted || $collected->cursor === null) {
            return PagingResponse::makeFinal($entries);
        }

        return PagingResponse::make(
            $entries,
            $this->sessions->keep(
                $pagingRequest,
                $session,
                $collected->cursor,
            ),
        );
    }

    /**
     * @throws OperationException
     */
    private function makePagingRequest(
        LdapMessageRequest $message,
        ?SortingResponseControl $sortResponse,
    ): PagingRequest {
        return new PagingRequest(
            $this->getPagingControlFromMessage($message),
            $this->getSearchRequestFromMessage($message),
            $this->controlsForBackend(
                $message,
                $sortResponse,
            ),
        );
    }
}
