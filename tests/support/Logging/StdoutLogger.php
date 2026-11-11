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

namespace Tests\Support\FreeDSx\Ldap\Logging;

use Psr\Log\AbstractLogger;
use Stringable;

use function fwrite;
use function is_string;
use function sprintf;

/**
 * Writes each log message to stdout, so a test can wait on one instead of sleeping.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class StdoutLogger extends AbstractLogger
{
    /**
     * @param mixed[] $context
     */
    public function log(
        $level,
        Stringable|string $message,
        array $context = [],
    ): void {
        fwrite(
            STDOUT,
            sprintf(
                "[%s] %s\n",
                is_string($level) ? $level : 'log',
                $message,
            ),
        );
    }
}
