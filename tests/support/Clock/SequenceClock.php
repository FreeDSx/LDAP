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

namespace Tests\Support\FreeDSx\Ldap\Clock;

use DateTimeImmutable;
use DateTimeZone;
use FreeDSx\Ldap\Server\Clock\ClockInterface;

use function count;
use function min;

/**
 * Test clock that answers each read with the next instant it was given, then keeps answering with the last.
 */
final class SequenceClock implements ClockInterface
{
    /**
     * @var list<DateTimeImmutable>
     */
    private array $instants = [];

    private int $reads = 0;

    public function __construct(
        string $first,
        string ...$rest,
    ) {
        foreach ([$first, ...$rest] as $instant) {
            $this->instants[] = new DateTimeImmutable(
                $instant,
                new DateTimeZone('UTC'),
            );
        }
    }

    public function now(): DateTimeImmutable
    {
        $instant = $this->instants[min(
            $this->reads,
            count($this->instants) - 1,
        )];
        $this->reads++;

        return $instant;
    }
}
