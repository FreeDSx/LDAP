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

namespace Tests\Unit\FreeDSx\Ldap\Server\Config\Storage;

use FreeDSx\Ldap\Server\Config\Storage\InMemoryStorageConfig;
use FreeDSx\Ldap\Server\Config\Storage\StorageType;
use PHPUnit\Framework\TestCase;

final class InMemoryStorageConfigTest extends TestCase
{
    public function test_its_type_is_in_memory(): void
    {
        self::assertSame(
            StorageType::InMemory,
            (new InMemoryStorageConfig())->type(),
        );
    }

    public function test_its_connections_hold_no_open_files(): void
    {
        self::assertSame(
            0,
            (new InMemoryStorageConfig())->descriptorsPerConnection(),
        );
    }
}
