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

namespace FreeDSx\Ldap\Server\PasswordPolicy;

use DateTimeImmutable;
use FreeDSx\Ldap\Server\Clock\ClockInterface;

/**
 * Stamps pwdFailureTime / pwdGraceUseTime values with real microseconds, unique for the entry as draft-behera password
 * policy recommends.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class UniquePolicyTimeFactory
{
    public function __construct(private ClockInterface $clock) {}

    /**
     * The current time, or just past the newest of $existing (read under the lock that persists the result) when it
     * would repeat or precede it.
     *
     * @param list<DateTimeImmutable> $existing
     */
    public function next(array $existing): DateTimeImmutable
    {
        $now = $this->clock->now();
        $newest = self::newest($existing);

        if ($newest === null || $now > $newest) {
            return $now;
        }

        return $newest->modify('+1 microsecond');
    }

    /**
     * @param list<DateTimeImmutable> $times
     */
    private static function newest(array $times): ?DateTimeImmutable
    {
        $newest = null;

        foreach ($times as $time) {
            if ($newest === null || $time > $newest) {
                $newest = $time;
            }
        }

        return $newest;
    }
}
