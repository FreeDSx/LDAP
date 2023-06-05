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

use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Operation\ResultCode;

final class SearchResult
{
    private Entries $entries;

    private string $baseDn;

    private int $resultCode;

    private string $diagnosticMessage;

    private function __construct(
        Entries $entries,
        string $baseDn = '',
        int $resultCode = ResultCode::SUCCESS,
        string $diagnosticMessage = ''
    ) {
        $this->entries = $entries;
        $this->baseDn = $baseDn;
        $this->resultCode = $resultCode;
        $this->diagnosticMessage = $diagnosticMessage;
    }

    /**
     * Make a successful server search result representation.
     */
    public static function makeSuccessResult(
        Entries $entries,
        string $baseDn = '',
        string $diagnosticMessage = ''
    ): self {
        return new self(
            $entries,
            $baseDn,
            ResultCode::SUCCESS,
            $diagnosticMessage
        );
    }

    /**
     * Make an error result for server search result representation. This could occur for any reason, such as a base DN
     * not existing. This result MUST not return a success result code.
     */
    public static function makeErrorResult(
        int $resultCode,
        string $baseDn = '',
        string $diagnosticMessage = '',
        ?Entries $entries = null
    ): self {
        if ($resultCode === ResultCode::SUCCESS) {
            throw new InvalidArgumentException('You must not return a success result code on a search error.');
        }

        return new self(
            $entries ?? new Entries(),
            $baseDn,
            $resultCode,
            $diagnosticMessage
        );
    }

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

    public function getBaseDn(): string
    {
        return $this->baseDn;
    }
}
