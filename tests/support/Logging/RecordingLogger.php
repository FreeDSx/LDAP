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

use FreeDSx\Ldap\Server\Logging\EventContext;
use Psr\Log\AbstractLogger;
use Stringable;

/**
 * In-memory PSR-3 logger that captures every record for inspection in tests.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class RecordingLogger extends AbstractLogger
{
    /**
     * @var list<array{level: string, message: string, context: array<string, mixed>}>
     */
    public array $records = [];

    /**
     * @param array<string, mixed> $context
     */
    public function log(
        mixed $level,
        string|Stringable $message,
        array $context = [],
    ): void {
        $this->records[] = [
            'level' => is_scalar($level) ? (string) $level : '',
            'message' => (string) $message,
            'context' => $context,
        ];
    }

    /**
     * The event each record names, in the order they were logged.
     *
     * @return list<mixed>
     */
    public function events(): array
    {
        return array_map(
            static fn(array $record): mixed => $record['context'][EventContext::EVENT] ?? null,
            $this->records,
        );
    }
}
