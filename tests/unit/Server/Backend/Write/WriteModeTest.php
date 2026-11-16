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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Write;

use FreeDSx\Ldap\Server\Backend\Write\BulkLoadOptions;
use FreeDSx\Ldap\Server\Backend\Write\WriteMode;
use PHPUnit\Framework\TestCase;

final class WriteModeTest extends TestCase
{
    public function test_a_client_write_is_not_a_system_write(): void
    {
        $mode = WriteMode::client();

        self::assertFalse($mode->isSystem());
        self::assertFalse($mode->keepsModifyMetadata());
        self::assertNull($mode->bulkLoadOptions());
    }

    public function test_a_system_write_stamps_the_modify_metadata(): void
    {
        $mode = WriteMode::system();

        self::assertTrue($mode->isSystem());
        self::assertFalse($mode->keepsModifyMetadata());
        self::assertNull($mode->bulkLoadOptions());
    }

    public function test_a_bookkeeping_write_is_a_system_write_keeping_the_modify_metadata(): void
    {
        $mode = WriteMode::bookkeeping();

        self::assertTrue($mode->isSystem());
        self::assertTrue($mode->keepsModifyMetadata());
        self::assertNull($mode->bulkLoadOptions());
    }

    public function test_a_bulk_load_is_a_system_write_carrying_its_options(): void
    {
        $options = new BulkLoadOptions(ignoreValidation: true);
        $mode = WriteMode::bulkLoad($options);

        self::assertTrue($mode->isSystem());
        self::assertFalse($mode->keepsModifyMetadata());
        self::assertSame(
            $options,
            $mode->bulkLoadOptions(),
        );
    }
}
