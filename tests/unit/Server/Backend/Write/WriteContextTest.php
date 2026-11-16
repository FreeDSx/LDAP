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

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Server\Backend\Write\BulkLoadOptions;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\SystemToken;
use PHPUnit\Framework\TestCase;

final class WriteContextTest extends TestCase
{
    public function test_a_context_given_no_mode_is_a_client_write(): void
    {
        $context = new WriteContext(
            new AnonToken(),
            new ControlBag(),
        );

        self::assertFalse($context->isSystem());
        self::assertFalse($context->keepsModifyMetadata());
        self::assertNull($context->bulkLoadOptions());
    }

    public function test_a_system_context_stamps_the_modify_metadata(): void
    {
        $context = WriteContext::system(
            new SystemToken(),
            new ControlBag(),
        );

        self::assertTrue($context->isSystem());
        self::assertFalse($context->keepsModifyMetadata());
    }

    public function test_a_bookkeeping_context_keeps_the_modify_metadata(): void
    {
        $context = WriteContext::bookkeeping(
            new SystemToken(),
            new ControlBag(),
        );

        self::assertTrue($context->isSystem());
        self::assertTrue($context->keepsModifyMetadata());
    }

    public function test_a_bulk_load_context_carries_its_options(): void
    {
        $options = new BulkLoadOptions();
        $context = WriteContext::bulkLoad(
            new SystemToken(),
            new ControlBag(),
            $options,
        );

        self::assertTrue($context->isSystem());
        self::assertSame(
            $options,
            $context->bulkLoadOptions(),
        );
    }

    public function test_a_context_without_its_control_evaluator_keeps_its_mode(): void
    {
        $context = WriteContext::bookkeeping(
            new SystemToken(),
            new ControlBag(),
        )->withoutControlEvaluator();

        self::assertTrue($context->isSystem());
        self::assertTrue($context->keepsModifyMetadata());
        self::assertNull($context->controlEvaluator());
    }
}
