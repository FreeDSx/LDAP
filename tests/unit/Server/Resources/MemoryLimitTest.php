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

namespace Tests\Unit\FreeDSx\Ldap\Server\Resources;

use FreeDSx\Ldap\Server\Resources\MemoryLimit;
use PHPUnit\Framework\TestCase;

final class MemoryLimitTest extends TestCase
{
    private string $memoryLimit = '';

    protected function setUp(): void
    {
        $this->memoryLimit = (string) ini_get('memory_limit');
    }

    protected function tearDown(): void
    {
        ini_set(
            'memory_limit',
            $this->memoryLimit,
        );
    }

    public function test_it_reads_the_memory_limit_of_this_process(): void
    {
        ini_set(
            'memory_limit',
            '4G',
        );

        self::assertSame(
            4_294_967_296,
            MemoryLimit::ofThisProcess()->getBytes(),
        );
    }

    public function test_a_process_without_a_memory_limit_has_none(): void
    {
        ini_set(
            'memory_limit',
            '-1',
        );

        self::assertNull(MemoryLimit::ofThisProcess()->getBytes());
    }

    public function test_it_is_reached_before_the_connections_and_held_requests_fit(): void
    {
        self::assertTrue((new MemoryLimit(1_000_000))->isReachedBefore(
            20,
            100_000,
        ));
    }

    public function test_it_is_not_reached_while_the_connections_and_held_requests_fit(): void
    {
        self::assertFalse((new MemoryLimit(1_000_000))->isReachedBefore(
            20,
            98_000,
        ));
    }

    public function test_it_is_reached_without_a_connection_limit(): void
    {
        self::assertTrue((new MemoryLimit(1_000_000))->isReachedBefore(
            0,
            100_000,
        ));
    }

    public function test_it_is_reached_without_a_held_request_size_limit(): void
    {
        self::assertTrue((new MemoryLimit(1_000_000))->isReachedBefore(
            1,
            0,
        ));
    }

    public function test_it_is_never_reached_without_a_memory_limit(): void
    {
        self::assertFalse((new MemoryLimit(null))->isReachedBefore(
            0,
            0,
        ));
    }
}
