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

namespace FreeDSx\Ldap\Server\PasswordPolicy\Replica\Forward;

use function min;

/**
 * Paces re-delivery of a subject the primary refused.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class RefusedForward
{
    /**
     * Ceiling on the gap. A refusal that clears is still noticed within a bounded number of drains.
     */
    private const MAX_SKIPPED_DRAINS = 64;

    private const MAX_DOUBLINGS = 30;

    private function __construct(
        public int $sequence,
        public int $attempts,
        public int $nextDrain,
    ) {}

    public static function after(
        int $sequence,
        int $drain,
        int $attempts = 1,
    ): self {
        $gap = min(
            1 << min($attempts - 1, self::MAX_DOUBLINGS),
            self::MAX_SKIPPED_DRAINS,
        );

        return new self(
            $sequence,
            $attempts,
            $drain + $gap,
        );
    }

    /**
     * Whether the subject is due for another attempt on this drain.
     */
    public function isDue(int $drain): bool
    {
        return $drain >= $this->nextDrain;
    }

    /**
     * Widens the gap so a refusal the primary keeps making costs progressively less.
     */
    public function again(int $drain): self
    {
        return self::after(
            $this->sequence,
            $drain,
            $this->attempts + 1,
        );
    }
}
