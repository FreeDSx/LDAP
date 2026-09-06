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

namespace FreeDSx\Ldap\Server\Paging;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\AttributeProjection;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerSearchTrait;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\FetchedEntry;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageCursor;
use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageSlice;
use FreeDSx\Ldap\Server\SearchLimits;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use Generator;

/**
 * Fills one page of a paged search from as many bounded reads as it takes.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PageFiller
{
    use ServerSearchTrait;

    public function __construct(
        private ReadBackendInterface $backend,
        private FilterEvaluatorInterface $filterEvaluator,
        private AccessControlInterface $accessControl,
        private Schema $schema,
        private SearchLimits $limits = new SearchLimits(),
    ) {}

    /**
     * Fills one page from $resumeFrom, reading bounded slices to their end so each says where it stopped.
     *
     * @throws OperationException
     */
    public function fill(
        PagingRequest $pagingRequest,
        TokenInterface $token,
        ?PageCursor $resumeFrom,
    ): CollectedPage {
        $request = $pagingRequest->getSearchRequest();
        $page = $this->startPage($pagingRequest, $resumeFrom);
        $budget = $this->budgetFor($request);
        $projection = $this->projectionFor($request);
        $exhausted = false;
        $hasFurtherMatch = false;

        while (!$exhausted) {
            $isFilling = $page->hasCapacity();

            // A full page only overflows the size limit if a further match exists
            if (!$isFilling && !$page->mayExceedSizeLimit()) {
                break;
            }

            $entries = $this->readSlice(
                $pagingRequest,
                $page->nextSlice($isFilling, $budget->deadline()),
                $budget->remainingLookthrough(),
            )->fetched();

            $end = $this->collectSlice(
                $entries,
                $page,
                $isFilling,
                $token,
                $request->getFilter(),
                $projection,
            );

            // The stream was abandoned mid-slice and can say nothing about where it stopped.
            if ($end === SliceEnd::FurtherMatch) {
                $hasFurtherMatch = true;

                break;
            }

            // The page took what it could and resumes from the last entry it placed.
            if ($end !== SliceEnd::Complete) {
                $page->abandonSlice($end);

                continue;
            }

            // A stream that reports nothing cannot be resumed, so the result has to be taken as finished.
            $read = $entries->getReturn();
            $exhausted = $read?->isExhausted() ?? true;
            $page->advanceTo($read?->cursor);
            $page->readCandidates($read->rows ?? 0);
            $budget->spend($read->rows ?? 0);
        }

        return $page->collected($exhausted, $hasFurtherMatch);
    }

    /**
     * Adds what this identity may see, reporting why the read stopped.
     *
     * @param Generator<int, FetchedEntry, mixed, mixed> $entries
     * @throws OperationException
     */
    private function collectSlice(
        Generator $entries,
        FillingPage $page,
        bool $isFilling,
        TokenInterface $token,
        FilterInterface $filter,
        AttributeProjection $projection,
    ): SliceEnd {
        foreach ($entries as $fetched) {
            $kept = $this->keepForPage(
                $fetched->entry,
                $token,
                $filter,
            );

            if ($kept === null) {
                continue;
            }

            if (!$isFilling) {
                return SliceEnd::FurtherMatch;
            }

            if (!$page->hasCapacity()) {
                return SliceEnd::PageFull;
            }

            if (!$page->canPlace($fetched->cursor)) {
                return SliceEnd::Unplaceable;
            }

            $page->add(
                $projection->project($kept),
                $fetched->cursor,
            );
        }

        return SliceEnd::Complete;
    }

    private function startPage(
        PagingRequest $pagingRequest,
        ?PageCursor $resumeFrom,
    ): FillingPage {
        $sizeLimit = $this->effectiveLimit(
            $pagingRequest->getSearchRequest()->getSizeLimit(),
            $this->limits->maxSearchSize(),
        );

        // Deliberate: the size limit bounds each page rather than the whole paged operation.
        $collectCap = $this->effectiveLimit(
            $this->effectiveLimit(
                $pagingRequest->getSize(),
                $this->limits->maxSearchPageSize(),
            ),
            $sizeLimit,
        );

        return new FillingPage(
            $collectCap > 0
                ? $collectCap
                : null,
            $sizeLimit,
            $this->limits->maxSearchPageSize(),
            $resumeFrom,
        );
    }

    private function budgetFor(SearchRequest $request): PageBudget
    {
        return PageBudget::of(
            $this->effectiveLimit(
                $request->getTimeLimit(),
                $this->limits->maxSearchTimeLimit(),
            ),
            $this->limits->effectivePagedLookthrough(),
        );
    }

    /**
     * @throws OperationException
     */
    private function readSlice(
        PagingRequest $pagingRequest,
        PageSlice $slice,
        int $lookthrough,
    ): EntryStream {
        return $this->backend->search(
            $pagingRequest->getSearchRequest(),
            $this->subentryVisibility($pagingRequest->controls()),
            $pagingRequest->controls(),
            new SearchLimits(
                maxSearchTimeLimit: $this->limits->maxSearchTimeLimit(),
                maxSearchLookthrough: $lookthrough,
            ),
            $slice,
        );
    }

    /**
     * The entry as this identity may see it, or null when it may not see it at all.
     *
     * @throws OperationException
     */
    private function keepForPage(
        Entry $entry,
        TokenInterface $token,
        FilterInterface $filter,
    ): ?Entry {
        $filtered = $this->accessControl->filterEntry(
            $token,
            $entry,
        );

        if ($filtered === null) {
            return null;
        }

        // Stripping an attribute can cost the entry its match, so a changed entry is judged against the filter again.
        return $filtered !== $entry && !$this->filterEvaluator->evaluate($filtered, $filter)
            ? null
            : $filtered;
    }

    private function projectionFor(SearchRequest $request): AttributeProjection
    {
        return AttributeProjection::forRequest(
            $request->getAttributes(),
            $request->getAttributesOnly(),
            $this->schema,
        );
    }
}
