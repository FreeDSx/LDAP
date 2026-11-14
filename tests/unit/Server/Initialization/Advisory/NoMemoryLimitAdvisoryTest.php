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

namespace Tests\Unit\FreeDSx\Ldap\Server\Initialization\Advisory;

use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\Initialization\Advisory\NoMemoryLimitAdvisory;
use FreeDSx\Ldap\Server\Initialization\InitializationWarning;
use FreeDSx\Ldap\Server\Logging\ConcurrencyLimitReason;
use FreeDSx\Ldap\Server\Resources\MemoryLimit;
use PHPUnit\Framework\TestCase;

final class NoMemoryLimitAdvisoryTest extends TestCase
{
    private const HELD_REQUEST_SIZE = 536_870_912;

    private NetworkConfig $network;

    protected function setUp(): void
    {
        $this->network = new NetworkConfig();
    }

    public function test_it_warns_that_the_held_request_size_is_fixed_without_a_memory_limit(): void
    {
        self::assertEquals(
            [
                InitializationWarning::concurrencyLimited(
                    ConcurrencyLimitReason::NoMemoryLimit,
                    ['max_held_request_size' => self::HELD_REQUEST_SIZE],
                ),
            ],
            $this->advisoryFor(new MemoryLimit(null))->warnings(),
        );
    }

    public function test_it_does_not_warn_with_a_memory_limit(): void
    {
        self::assertSame(
            [],
            $this->advisoryFor(new MemoryLimit(1_073_741_824))->warnings(),
        );
    }

    public function test_it_does_not_warn_when_the_held_request_size_is_configured(): void
    {
        $this->network->setMaxHeldRequestSize(self::HELD_REQUEST_SIZE);

        self::assertSame(
            [],
            $this->advisoryFor(new MemoryLimit(null))->warnings(),
        );
    }

    private function advisoryFor(MemoryLimit $memoryLimit): NoMemoryLimitAdvisory
    {
        return new NoMemoryLimitAdvisory(
            $this->network,
            $memoryLimit,
            self::HELD_REQUEST_SIZE,
        );
    }
}
