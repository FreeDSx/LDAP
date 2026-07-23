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

use FreeDSx\Ldap\Server\Backend\Storage\Config\JsonStorageConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Config\StorageType;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

final class JsonStorageConfigTest extends TestCase
{
    public function test_its_type_is_json(): void
    {
        self::assertSame(
            StorageType::Json,
            JsonStorageConfig::forFile('/tmp/ldap.json')->type(),
        );
    }

    public function test_it_carries_the_file_path(): void
    {
        self::assertSame(
            '/tmp/ldap.json',
            JsonStorageConfig::forFile('/tmp/ldap.json')->path(),
        );
    }

    public function test_it_has_no_logger_by_default(): void
    {
        self::assertNull(JsonStorageConfig::forFile('/tmp/ldap.json')->logger());
    }

    public function test_it_carries_the_given_logger(): void
    {
        $logger = new NullLogger();

        self::assertSame(
            $logger,
            JsonStorageConfig::forFile(
                '/tmp/ldap.json',
                $logger,
            )->logger(),
        );
    }
}
