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
use FreeDSx\Ldap\Server\Backend\Storage\Derived\DerivedAttributeTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Derived\DerivedResolver;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\TimeLimitExceededException;
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

    public function buildForBaseObject(
        Entry $entry,
        SearchRequest $request,
    ): EntryStream {
        return new EntryStream(
            $this->yieldSingle($this->injectDerived($entry, $request)),
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

        // Only unchecked candidates are counted: a backend that answered the filter itself looked through nothing.
        if (!$stream->isPreFiltered) {
            $generator = $this->wrapWithLookthrough(
                $generator,
                $effectiveLimits,
            );
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
     * @param Generator<Entry> $generator
     * @return Generator<Entry>
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
        $requested = $this->requestedDerived($request);

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
     * Derived attribute names the request asks for, by name, by OID, or through the operational wildcard.
     *
     * @return list<string>
     */
    private function requestedDerived(SearchRequest $request): array
    {
        $attributes = $request->getAttributes();
        $wantsAllOperational = $this->namesAny(
            $attributes,
            SearchRequest::ATTRIBUTES_ALL_OPERATIONAL,
        );
        $requested = [];

        foreach (array_keys(self::DERIVED_ATTRIBUTE_OIDS) as $name) {
            if ($wantsAllOperational || $this->namesAny($attributes, $name)) {
                $requested[] = $name;
            }
        }

        return $requested;
    }

    /**
     * Whether any requested description names the given type, allowing for its OID and its options.
     *
     * @param array<Attribute> $attributes
     */
    private function namesAny(
        array $attributes,
        string $name,
    ): bool {
        foreach ($attributes as $attr) {
            if (self::describesType($attr->getName(), $name)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param Generator<Entry> $generator
     * @return Generator<Entry>
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
     * @param Generator<Entry> $generator
     * @return Generator<Entry>
     * @throws OperationException
     */
    private function wrapWithLookthrough(
        Generator $generator,
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

            yield $entry;
        }

        return $generator->getReturn();
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

        return $generator->getReturn();
    }

    /**
     * @return Generator<Entry>
     */
    private function yieldSingle(Entry $entry): Generator
    {
        yield $entry;
    }
}
