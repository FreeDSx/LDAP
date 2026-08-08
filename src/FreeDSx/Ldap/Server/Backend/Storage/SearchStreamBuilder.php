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

namespace FreeDSx\Ldap\Server\Backend\Storage;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\TimeLimitExceededException;
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
        private EntryStorageInterface $storage,
        private SearchLimits $limits,
        private FilterEvaluatorInterface $filterEvaluator,
    ) {}

    public function buildForBaseObject(
        Entry $entry,
        SearchRequest $request,
    ): EntryStream {
        $entry = $this->requestsHasSubordinates($request)
            ? $this->injectHasSubordinates($entry)
            : $entry;

        return new EntryStream($this->yieldSingle($entry));
    }

    /**
     * @throws OperationException
     */
    public function buildForList(
        EntryStream $stream,
        SearchRequest $request,
        ?SearchLimits $effectiveLimits = null,
    ): EntryStream {
        $generator = $stream->entries;

        // In-search alias dereferencing is not supported. Decline rather than silently return the alias.
        if ($this->derefsInSearch($request)) {
            $generator = $this->wrapWithAliasDecline($generator);
        }

        $generator = $this->wrapWithTimeLimitHandling($generator);

        if (!$stream->isPreFiltered) {
            $generator = $this->wrapWithFilterEvaluation(
                $generator,
                $request->getFilter(),
                $effectiveLimits,
            );
        }

        if ($this->requestsHasSubordinates($request)) {
            $generator = $this->wrapWithHasSubordinates($generator);
        }

        return new EntryStream(
            $generator,
            true,
        );
    }

    private function requestsHasSubordinates(SearchRequest $request): bool
    {
        foreach ($request->getAttributes() as $attr) {
            if ($this->isHasSubordinatesAttribute($attr)) {
                return true;
            }
        }

        return false;
    }

    private function isHasSubordinatesAttribute(Attribute $attr): bool
    {
        return strcasecmp($attr->getName(), '+') === 0
            || strcasecmp($attr->getName(), 'hasSubordinates') === 0;
    }

    private function injectHasSubordinates(Entry $entry): Entry
    {
        $copy = $entry->makeCopy();
        $copy->set(
            'hasSubordinates',
            $this->storage->hasChildren($entry->getDn())
                ? 'TRUE'
                : 'FALSE',
        );

        return $copy;
    }

    private function derefsInSearch(SearchRequest $request): bool
    {
        $deref = $request->getDereferenceAliases();

        return $deref === SearchRequest::DEREF_IN_SEARCHING
            || $deref === SearchRequest::DEREF_ALWAYS;
    }

    /**
     * @param Generator<Entry> $generator
     * @return Generator<Entry>
     * @throws OperationException
     */
    private function wrapWithAliasDecline(Generator $generator): Generator
    {
        foreach ($generator as $entry) {
            if (AliasDetector::isAlias($entry)) {
                throw new OperationException(
                    'Alias dereferencing is not supported.',
                    ResultCode::ALIAS_DEREFERENCING_PROBLEM,
                );
            }

            yield $entry;
        }
    }

    /**
     * @param Generator<Entry> $generator
     * @return Generator<Entry>
     * @throws OperationException
     */
    private function wrapWithFilterEvaluation(
        Generator $generator,
        FilterInterface $filter,
        ?SearchLimits $effectiveLimits = null,
    ): Generator {
        $lookthrough = ($effectiveLimits ?? $this->limits)->maxSearchLookthrough;
        $examined = 0;

        foreach ($generator as $entry) {
            if ($lookthrough > 0 && ++$examined > $lookthrough) {
                throw new OperationException(
                    'Administrative limit exceeded.',
                    ResultCode::ADMIN_LIMIT_EXCEEDED,
                );
            }

            if ($this->filterEvaluator->evaluate($entry, $filter)) {
                yield $entry;
            }
        }
    }

    /**
     * @param Generator<Entry> $generator
     * @return Generator<Entry>
     */
    private function wrapWithHasSubordinates(Generator $generator): Generator
    {
        foreach ($generator as $entry) {
            yield $this->injectHasSubordinates($entry);
        }
    }

    /**
     * @param Generator<Entry> $generator
     * @return Generator<Entry>
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
    }

    /**
     * @return Generator<Entry>
     */
    private function yieldSingle(Entry $entry): Generator
    {
        yield $entry;
    }
}
