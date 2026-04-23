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

final class SearchResult
{
    /**
     * @param iterable<Entry> $entries
     */
    private function __construct(
        private readonly iterable $entries,
        private readonly SearchResultState $state,
        private readonly string $baseDn = '',
    ) {
    }

    /**
     * Successful server search result. The final result code may still be flipped to
     * SIZE_LIMIT_EXCEEDED by the streaming producer via the shared SearchResultState.
     *
     * @param iterable<Entry> $entries
     */
    public static function makeSuccessResult(
        iterable $entries,
        string $baseDn = '',
        ?SearchResultState $state = null,
    ): self {
        return new self(
            $entries,
            $state ?? new SearchResultState(),
            $baseDn,
        );
    }

    /**
     * Error result for a server search. Must not carry the SUCCESS code.
     *
     * @param ?iterable<Entry> $entries
     */
    public static function makeErrorResult(
        int $resultCode,
        string $baseDn = '',
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
            $baseDn,
        );
    }

    /**
     * Terminal result where the client's sizeLimit was reached; partial entries are included.
     *
     * @param iterable<Entry> $entries
     */
    public static function makeSizeLimitResult(
        iterable $entries,
        string $baseDn = '',
    ): self {
        return new self(
            $entries,
            new SearchResultState(resultCode: ResultCode::SIZE_LIMIT_EXCEEDED),
            $baseDn,
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

    public function getBaseDn(): string
    {
        return $this->baseDn;
    }
}
