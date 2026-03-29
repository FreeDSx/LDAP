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

namespace FreeDSx\Ldap\Server\RequestHandler;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\ResultCode;

/**
 * Represents the search result to be returned from a request handler search.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SearchResult
{
    /**
     * @param Entries<Entry> $entries
     * @param Control[] $controls
     */
    private function __construct(
        private readonly Entries $entries,
        private readonly int $resultCode,
        private readonly string $diagnosticMessage,
        private readonly array $controls,
    ) {
    }

    /**
     * Make a successful search result — the common case.
     *
     * @param Entries<Entry> $entries
     */
    public static function make(
        Entries $entries,
        Control ...$controls,
    ): self {
        return new self(
            $entries,
            ResultCode::SUCCESS,
            '',
            $controls,
        );
    }

    /**
     * Make a search result with an explicit result code. Use for partial results, size/time limit exceeded, referrals,
     * etc. Entries are still returned to the client before the SearchResultDone.
     *
     * @param Entries<Entry> $entries
     */
    public static function makeWithResultCode(
        Entries $entries,
        int $resultCode,
        string $diagnosticMessage = '',
        Control ...$controls,
    ): self {
        return new self(
            $entries,
            $resultCode,
            $diagnosticMessage,
            $controls,
        );
    }

    /**
     * @return Entries<Entry>
     */
    public function getEntries(): Entries
    {
        return $this->entries;
    }

    public function getResultCode(): int
    {
        return $this->resultCode;
    }

    public function getDiagnosticMessage(): string
    {
        return $this->diagnosticMessage;
    }

    /**
     * @return Control[]
     */
    public function getControls(): array
    {
        return $this->controls;
    }
}
