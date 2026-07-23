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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Config;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Config\InMemoryStorageConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Config\StorageType;
use PHPUnit\Framework\TestCase;

final class InMemoryStorageConfigTest extends TestCase
{
    public function test_its_type_is_in_memory(): void
    {
        self::assertSame(
            StorageType::InMemory,
            InMemoryStorageConfig::withEntries()->type(),
        );
    }

    public function test_it_defaults_to_no_entries(): void
    {
        self::assertSame(
            [],
            InMemoryStorageConfig::withEntries()->entries(),
        );
    }

    public function test_it_carries_the_given_entries(): void
    {
        $entries = [Entry::fromArray('dc=example,dc=com')];

        self::assertSame(
            $entries,
            InMemoryStorageConfig::withEntries($entries)->entries(),
        );
    }
}
