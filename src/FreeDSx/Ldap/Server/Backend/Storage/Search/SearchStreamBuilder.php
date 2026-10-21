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

namespace FreeDSx\Ldap\Server\Backend\Storage\Search;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Derived\DerivedResolver;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\TimeLimitExceededException;
use FreeDSx\Ldap\Server\Backend\Storage\FetchedBatch;
use FreeDSx\Ldap\Server\Backend\Storage\FetchedEntry;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\LinkedLeafWitness;
use FreeDSx\Ldap\Server\SearchLimits;
use Generator;

/**
 * Builds EntryStreams for search operations.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SearchStreamBuilder
{
    /**
     * @param FilterEvaluatorInterface $filterEvaluator Must know the configured schema, or matching rules are ignored.
     */
    public function __construct(
        private SearchLimits $limits,
        private FilterEvaluatorInterface $filterEvaluator,
        private DerivedResolver $derivedResolver,
        private LinkedLeafWitness $linkedLeaves,
    ) {}

    /**
     * @throws OperationException
     */
    public function buildForBaseObject(
        Entry $entry,
        SearchRequest $request,
    ): EntryStream {
        // RFC 4511 §4.5.1 applies the filter at every scope, and derived attributes are injected after it
        return EntryStream::positioned(
            $this->examined(
                $this->yieldSingle($entry),
                $request,
                $request->getFilter(),
                0,
            ),
            true,
        );
    }

    /**
     * @throws OperationException
     */
    public function buildForList(
        EntryStream $stream,
        SearchRequest $request,
        ?SearchLimits $effectiveLimits = null,
    ): EntryStream {
        // In-search alias dereferencing is not implemented, so an alias is returned as the ordinary entry it is
        // rather than failing the search. This is a deliberate RFC difference.
        return EntryStream::positioned(
            $this->examined(
                $stream->fetched(),
                $request,
                $stream->isPreFiltered
                    ? null
                    : $request->getFilter(),
                ($effectiveLimits ?? $this->limits)->maxSearchLookthrough(),
            ),
            true,
        );
    }

    /**
     * Charges each candidate to the lookthrough, applies the filter storage left, and injects derived attributes.
     *
     * @param Generator<int, FetchedEntry, mixed, ?FetchedBatch> $candidates
     * @param ?FilterInterface $filter Null when storage already applied it.
     * @param int $lookthrough The candidates that may be examined, or 0 for no limit.
     * @return Generator<int, FetchedEntry, mixed, ?FetchedBatch>
     * @throws OperationException
     */
    private function examined(
        Generator $candidates,
        SearchRequest $request,
        ?FilterInterface $filter,
        int $lookthrough,
    ): Generator {
        $derived = $this->derivedResolver->requested($request->getAttributes());
        $examined = 0;

        try {
            foreach ($candidates as $fetched) {
                if ($lookthrough > 0 && ++$examined > $lookthrough) {
                    throw new OperationException(
                        'Administrative limit exceeded.',
                        ResultCode::ADMIN_LIMIT_EXCEEDED,
                    );
                }

                if ($filter !== null && !$this->matches($fetched->entry, $filter)) {
                    continue;
                }

                if ($derived !== []) {
                    $fetched = new FetchedEntry(
                        $this->derivedResolver->inject(
                            $fetched->entry,
                            $derived,
                        ),
                        $fetched->cursor,
                    );
                }

                yield $fetched;
            }
        } catch (TimeLimitExceededException) {
            throw new OperationException(
                'Time limit exceeded.',
                ResultCode::TIME_LIMIT_EXCEEDED,
            );
        }

        return $candidates->getReturn();
    }

    /**
     * @throws OperationException
     */
    private function matches(
        Entry $entry,
        FilterInterface $filter,
    ): bool {
        return $this->filterEvaluator->evaluate(
            $this->linkedLeaves->witness(
                $entry,
                $filter,
            ),
            $filter,
        );
    }

    /**
     * @return Generator<int, FetchedEntry, mixed, ?FetchedBatch>
     */
    private function yieldSingle(Entry $entry): Generator
    {
        yield new FetchedEntry($entry);

        // A base-object read is one entry, so there is never anywhere to resume from.
        return null;
    }
}
