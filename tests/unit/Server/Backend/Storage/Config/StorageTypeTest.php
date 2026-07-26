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

use FreeDSx\Ldap\Server\Backend\Storage\Config\StorageType;
use PHPUnit\Framework\TestCase;

final class StorageTypeTest extends TestCase
{
    public function test_database_backed_storage_can_be_shared_between_processes(): void
    {
        self::assertTrue(StorageType::Pdo->isMultiProcessSafe());
    }

    public function test_file_backed_storage_cannot_be_shared_between_processes(): void
    {
        self::assertFalse(StorageType::Json->isMultiProcessSafe());
    }

    public function test_heap_backed_storage_cannot_be_shared_between_processes(): void
    {
        self::assertFalse(StorageType::InMemory->isMultiProcessSafe());
    }
}
