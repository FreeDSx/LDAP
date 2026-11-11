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

namespace Tests\Unit\FreeDSx\Ldap\Server\ServerRunner;

use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\ServerRunner\AcceptBackoff;
use FreeDSx\Socket\Exception\AcceptException;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;

final class AcceptBackoffTest extends TestCase
{
    private RecordingLogger $logger;

    private EventLogger $events;

    private AcceptBackoff $subject;

    protected function setUp(): void
    {
        $this->logger = new RecordingLogger();
        $this->events = new EventLogger(
            $this->logger,
            EventLogPolicy::default(),
        );
        $this->subject = new AcceptBackoff();
    }

    public function test_the_first_failure_waits_ten_milliseconds_and_is_logged(): void
    {
        self::assertSame(
            0.01,
            $this->failAccept(),
        );
        self::assertSame(
            [ServerEvent::ServerAcceptFailed->value],
            $this->loggedEvents(),
        );
    }

    public function test_each_further_failure_doubles_the_wait_up_to_a_second_without_logging_again(): void
    {
        $waits = [];
        for ($i = 0; $i < 9; $i++) {
            $waits[] = $this->failAccept();
        }

        self::assertSame(
            [0.01, 0.02, 0.04, 0.08, 0.16, 0.32, 0.64, 1.0, 1.0],
            $waits,
        );
        self::assertSame(
            [ServerEvent::ServerAcceptFailed->value],
            $this->loggedEvents(),
        );
    }

    public function test_an_accept_after_failures_logs_the_recovery_with_their_count_and_starts_over(): void
    {
        $this->failAccept();
        $this->failAccept();

        $this->subject->accepted($this->events);

        self::assertSame(
            [
                ServerEvent::ServerAcceptFailed->value,
                ServerEvent::ServerAcceptRecovered->value,
            ],
            $this->loggedEvents(),
        );
        self::assertSame(
            2,
            $this->logger->records[1]['context']['failures'] ?? null,
        );
        self::assertSame(
            0.01,
            $this->failAccept(),
        );
    }

    public function test_an_accept_without_failures_logs_nothing(): void
    {
        $this->subject->accepted($this->events);

        self::assertSame(
            [],
            $this->loggedEvents(),
        );
    }

    private function failAccept(): float
    {
        return $this->subject->failed(
            new AcceptException('Unable to accept a waiting client: Too many open files'),
            $this->events,
        );
    }

    /**
     * @return list<mixed>
     */
    private function loggedEvents(): array
    {
        return array_map(
            static fn(array $record): mixed => $record['context'][EventContext::EVENT] ?? null,
            $this->logger->records,
        );
    }
}
