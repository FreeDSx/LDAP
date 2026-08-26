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

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\SystemChange\SystemChangeWriter;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\Token\SystemToken;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Backend\RecordingWriteHandler;

final class SystemChangeWriterTest extends TestCase
{
    private RecordingWriteHandler $handler;

    private SystemChangeWriter $subject;

    protected function setUp(): void
    {
        $this->handler = new RecordingWriteHandler();
        $this->subject = new SystemChangeWriter($this->handler);
    }

    public function test_empty_changes_dispatch_nothing(): void
    {
        $this->subject->write(
            new Dn('cn=foo,dc=example,dc=com'),
            OperationalChanges::none(),
        );

        self::assertSame(
            [],
            $this->handler->dispatched,
        );
    }

    public function test_dispatches_update_command_for_the_dn(): void
    {
        $dn = new Dn('cn=foo,dc=example,dc=com');
        $change = Change::replace(
            'pwdFailureTime',
            '20260520120000Z',
        );

        $this->subject->write(
            $dn,
            OperationalChanges::of($change),
        );

        self::assertCount(
            1,
            $this->handler->dispatched,
        );
        $request = $this->handler->dispatched[0]['request'];
        self::assertInstanceOf(
            UpdateCommand::class,
            $request,
        );
        self::assertSame(
            $dn,
            $request->dn,
        );
        self::assertSame(
            [$change],
            $request->changes,
        );
    }

    public function test_dispatch_uses_a_system_flagged_context(): void
    {
        $this->subject->write(
            new Dn('cn=foo,dc=example,dc=com'),
            OperationalChanges::of(Change::reset('pwdFailureTime')),
        );

        $context = $this->handler->dispatched[0]['context'];

        self::assertTrue($context->isSystem());
        self::assertSame(
            SystemToken::IDENTITY,
            $context->getBoundDn(),
        );
    }
}
