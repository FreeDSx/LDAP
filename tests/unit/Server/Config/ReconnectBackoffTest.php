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

namespace Tests\Unit\FreeDSx\Ldap\Server\Config;

use FreeDSx\Ldap\Server\Config\ReconnectBackoff;
use PHPUnit\Framework\TestCase;

final class ReconnectBackoffTest extends TestCase
{
    public function test_initial_returns_the_base_delay(): void
    {
        self::assertSame(
            2.0,
            (new ReconnectBackoff(baseSeconds: 2.0))->initial(),
        );
    }

    public function test_next_doubles_the_current_delay(): void
    {
        self::assertSame(
            4.0,
            (new ReconnectBackoff())->next(2.0),
        );
    }

    public function test_next_caps_at_the_maximum(): void
    {
        self::assertSame(
            30.0,
            (new ReconnectBackoff(maxSeconds: 30.0))->next(20.0),
        );
    }
}
