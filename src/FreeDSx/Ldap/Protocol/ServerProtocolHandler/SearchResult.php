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
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Operation\ResultCode;

final readonly class SearchResult
{
    /**
     * @param iterable<Entry> $entries
     */
    private function __construct(
        private iterable $entries,
        private SearchResultState $state,
        private string $matchedDn = '',
    ) {}

    /**
     * Successful server search result. The final result code may still be flipped to
     * SIZE_LIMIT_EXCEEDED by the streaming producer via the shared SearchResultState.
     *
     * @param iterable<Entry> $entries
     */
    public static function makeSuccessResult(
        iterable $entries,
        ?SearchResultState $state = null,
    ): self {
        return new self(
            $entries,
            $state ?? new SearchResultState(),
        );
    }

    /**
     * Error result for a server search. Must not carry the SUCCESS code.
     *
     * @param ?iterable<Entry> $entries
     */
    public static function makeErrorResult(
        int $resultCode,
        string $matchedDn = '',
        string $diagnosticMessage = '',
        ?iterable $entries = null,
    ): self {
        if ($resultCode === ResultCode::SUCCESS) {
            throw new InvalidArgumentException('You must not return a success result code on a search error.');
        }

        return new self(
            $entries ?? [],
            new SearchResultState(
                resultCode: $resultCode,
                diagnosticMessage: $diagnosticMessage,
            ),
            $matchedDn,
        );
    }

    /**
     * Terminal result where the client's sizeLimit was reached; partial entries are included.
     *
     * @param iterable<Entry> $entries
     */
    public static function makeSizeLimitResult(iterable $entries): self
    {
        return new self(
            $entries,
            new SearchResultState(resultCode: ResultCode::SIZE_LIMIT_EXCEEDED),
        );
    }

    /**
     * @return iterable<Entry>
     */
    public function getEntries(): iterable
    {
        return $this->entries;
    }

    public function getState(): SearchResultState
    {
        return $this->state;
    }

    /**
     * Empty unless the target could not be named, which is the only case RFC 4511 §4.1.9 fills matchedDN for.
     */
    public function getMatchedDn(): string
    {
        return $this->matchedDn;
    }
}
