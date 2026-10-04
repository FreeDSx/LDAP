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

namespace FreeDSx\Ldap\Server\Process\Child;

use FreeDSx\Ldap\Server\Metrics\Observation\ConnectionObservation;

use function is_int;
use function pcntl_wexitstatus;
use function pcntl_wifexited;

/**
 * The exit codes a connection child ends with, so the parent learns why the connection closed and can count it.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum ChildExitCode: int
{
    case WriteTimeout = 10;

    case IdleTimeout = 11;

    case RequestSizeExceeded = 12;

    case ProtocolError = 13;

    /**
     * Zero when the close reason is not one the parent counts.
     */
    public static function forCloseReason(?ConnectionObservation $closeReason): int
    {
        return match ($closeReason) {
            ConnectionObservation::WriteTimeout => self::WriteTimeout->value,
            ConnectionObservation::IdleTimeout => self::IdleTimeout->value,
            ConnectionObservation::RequestSizeExceeded => self::RequestSizeExceeded->value,
            ConnectionObservation::ProtocolError => self::ProtocolError->value,
            default => 0,
        };
    }

    /**
     * The close reason a reaped child reported through its wait status, if it exited with one.
     *
     * @param mixed $status The status pcntl_waitpid() wrote back.
     */
    public static function closeReasonFor(mixed $status): ?ConnectionObservation
    {
        $code = is_int($status) && pcntl_wifexited($status)
            ? pcntl_wexitstatus($status)
            : false;

        if ($code === false) {
            return null;
        }

        return self::tryFrom($code)?->closeReason();
    }

    public function closeReason(): ConnectionObservation
    {
        return match ($this) {
            self::WriteTimeout => ConnectionObservation::WriteTimeout,
            self::IdleTimeout => ConnectionObservation::IdleTimeout,
            self::RequestSizeExceeded => ConnectionObservation::RequestSizeExceeded,
            self::ProtocolError => ConnectionObservation::ProtocolError,
        };
    }
}
