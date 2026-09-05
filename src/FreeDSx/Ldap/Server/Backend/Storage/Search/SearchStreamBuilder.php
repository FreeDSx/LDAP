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
use FreeDSx\Ldap\Server\Backend\Storage\Derived\DerivedAttributeTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Derived\DerivedResolver;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\TimeLimitExceededException;
use FreeDSx\Ldap\Server\Backend\Storage\FetchedBatch;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\SearchLimits;
use Generator;

/**
 * Builds EntryStreams for search operations.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SearchStreamBuilder
{
    use DerivedAttributeTrait;

    /**
     * @param FilterEvaluatorInterface $filterEvaluator Must know the configured schema, or matching rules are ignored.
     */
    public function __construct(
        private SearchLimits $limits,
        private FilterEvaluatorInterface $filterEvaluator,
        private DerivedResolver $derivedResolver,
    ) {}

    /**
     * @throws OperationException
     */
    public function buildForBaseObject(
        Entry $entry,
        SearchRequest $request,
    ): EntryStream {
        // RFC 4511 §4.5.1 applies the filter at every scope, and derived attributes are injected after it
        $generator = $this->wrapWithFilterEvaluation(
            $this->yieldSingle($entry),
            $request->getFilter(),
        );

        return new EntryStream(
            $this->wrapWithDerived(
                $generator,
                $request,
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
        $generator = $this->wrapWithTimeLimitHandling($stream->entries);

        // Every candidate examined is charged.
        $generator = $this->wrapWithLookthrough(
            $generator,
            $effectiveLimits,
        );

        if (!$stream->isPreFiltered) {
            $generator = $this->wrapWithFilterEvaluation(
                $generator,
                $request->getFilter(),
            );
        }

        $generator = $this->wrapWithDerived($generator, $request);

        return new EntryStream(
            $generator,
            true,
        );
    }

    /**
     * @param Generator<int, Entry, mixed, ?FetchedBatch> $generator
     * @return Generator<int, Entry, mixed, ?FetchedBatch>
     */
    private function wrapWithDerived(
        Generator $generator,
        SearchRequest $request,
    ): Generator {
        foreach ($generator as $entry) {
            yield $this->injectDerived($entry, $request);
        }

        return $generator->getReturn();
    }

    /**
     * Operational attributes held by nothing in storage, so they are computed per read and only when asked for.
     */
    private function injectDerived(
        Entry $entry,
        SearchRequest $request,
    ): Entry {
        $requested = self::derivedTypesRequested($request->getAttributes());

        if ($requested === []) {
            return $entry;
        }

        $copy = $entry->makeCopy();

        foreach ($requested as $name) {
            $copy->set(
                $name,
                $this->derivedResolver->resolve(
                    $name,
                    $entry,
                ),
            );
        }

        return $copy;
    }

    /**
     * @param Generator<int, Entry, mixed, ?FetchedBatch> $generator
     * @return Generator<int, Entry, mixed, ?FetchedBatch>
     * @throws OperationException
     */
    private function wrapWithFilterEvaluation(
        Generator $generator,
        FilterInterface $filter,
    ): Generator {
        foreach ($generator as $entry) {
            if ($this->filterEvaluator->evaluate($entry, $filter)) {
                yield $entry;
            }
        }

        return $generator->getReturn();
    }

    /**
     * @param Generator<int, Entry, mixed, ?FetchedBatch> $generator
     * @return Generator<int, Entry, mixed, ?FetchedBatch>
     * @throws OperationException
     */
    private function wrapWithLookthrough(
        Generator $generator,
        ?SearchLimits $effectiveLimits = null,
    ): Generator {
        $lookthrough = ($effectiveLimits ?? $this->limits)->maxSearchLookthrough();
        $examined = 0;

        foreach ($generator as $entry) {
            if ($lookthrough > 0 && ++$examined > $lookthrough) {
                throw new OperationException(
                    'Administrative limit exceeded.',
                    ResultCode::ADMIN_LIMIT_EXCEEDED,
                );
            }

            yield $entry;
        }

        return $generator->getReturn();
    }

    /**
     * @param Generator<int, Entry, mixed, ?FetchedBatch> $generator
     * @return Generator<int, Entry, mixed, ?FetchedBatch>
     * @throws OperationException
     */
    private function wrapWithTimeLimitHandling(Generator $generator): Generator
    {
        try {
            foreach ($generator as $entry) {
                yield $entry;
            }
        } catch (TimeLimitExceededException) {
            throw new OperationException(
                'Time limit exceeded.',
                ResultCode::TIME_LIMIT_EXCEEDED,
            );
        }

        return $generator->getReturn();
    }

    /**
     * @return Generator<int, Entry, mixed, ?FetchedBatch>
     */
    private function yieldSingle(Entry $entry): Generator
    {
        yield $entry;

        // A base-object read is one entry, so there is never anywhere to resume from.
        return null;
    }
}
