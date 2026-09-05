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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;

use function microtime;

/**
 * What one page may spend for the lookthrough. Held across every slice it is filled from.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PageBudget
{
    private int $examined = 0;

    private function __construct(
        private readonly ?float $deadline,
        private readonly int $maxLookthrough,
    ) {}

    /**
     * @param int $timeLimit Seconds the page may take, already resolved against the server maximum; zero is unbounded.
     * @param int $maxLookthrough Candidates the page may examine; zero is unbounded.
     */
    public static function of(
        int $timeLimit,
        int $maxLookthrough,
    ): self {
        return new self(
            $timeLimit > 0
                ? microtime(true) + $timeLimit
                : null,
            $maxLookthrough,
        );
    }

    /**
     * When the page must stop, or null when nothing bounds its time.
     */
    public function deadline(): ?float
    {
        return $this->deadline;
    }

    /**
     * What is left to examine, for a read that must not spend more than the page has.
     *
     * @throws OperationException
     */
    public function remainingLookthrough(): int
    {
        if ($this->maxLookthrough <= 0) {
            return 0;
        }

        if ($this->examined >= $this->maxLookthrough) {
            throw new OperationException(
                'Administrative limit exceeded.',
                ResultCode::ADMIN_LIMIT_EXCEEDED,
            );
        }

        return $this->maxLookthrough - $this->examined;
    }

    public function spend(int $candidates): void
    {
        $this->examined += $candidates;
    }
}
