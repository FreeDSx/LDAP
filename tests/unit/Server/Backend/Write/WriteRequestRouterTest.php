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

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Server\Backend\Write\WritableLdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestRouter;
use FreeDSx\Ldap\Server\Token\SystemToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class WriteRequestRouterTest extends TestCase
{
    private const DN = 'cn=foo,dc=example,dc=com';

    private WritableLdapBackendInterface&MockObject $backend;

    private WriteHandlerInterface&MockObject $writeHandler;

    private WriteRequestRouter $subject;

    protected function setUp(): void
    {
        $this->backend = $this->createMock(WritableLdapBackendInterface::class);
        $this->writeHandler = $this->createMock(WriteHandlerInterface::class);
        $this->writeHandler
            ->method('supports')
            ->willReturn(true);

        $this->subject = new WriteRequestRouter(
            $this->backend,
            new WriteOperationDispatcher($this->writeHandler),
        );
    }

    public function test_a_delete_carrying_the_subtree_control_removes_the_whole_subtree(): void
    {
        $this->backend
            ->expects(self::once())
            ->method('deleteSubtree');
        $this->writeHandler
            ->expects(self::never())
            ->method('handle');

        $this->subject->route(
            new DeleteRequest(self::DN),
            $this->contextWith(new Control(Control::OID_SUBTREE_DELETE)),
            static function (Dn $dn): void {},
        );
    }

    public function test_a_delete_without_the_subtree_control_goes_to_the_write_handler(): void
    {
        $this->backend
            ->expects(self::never())
            ->method('deleteSubtree');
        $this->writeHandler
            ->expects(self::once())
            ->method('handle');

        $this->subject->route(
            new DeleteRequest(self::DN),
            $this->contextWith(),
            static function (Dn $dn): void {},
        );
    }

    public function test_the_subtree_control_on_another_operation_is_not_routed_as_a_subtree_delete(): void
    {
        $this->backend
            ->expects(self::never())
            ->method('deleteSubtree');
        $this->writeHandler
            ->expects(self::once())
            ->method('handle');

        $this->subject->route(
            new AddRequest(Entry::create(self::DN)),
            $this->contextWith(new Control(Control::OID_SUBTREE_DELETE)),
            static function (Dn $dn): void {},
        );
    }

    public function test_the_subtree_delete_is_given_the_callers_authorization_check(): void
    {
        $authorized = false;
        $this->backend
            ->method('deleteSubtree')
            ->willReturnCallback(static function (
                object $command,
                WriteContext $context,
                callable $authorize,
            ): void {
                $authorize(new Dn(self::DN));
            });

        $this->subject->route(
            new DeleteRequest(self::DN),
            $this->contextWith(new Control(Control::OID_SUBTREE_DELETE)),
            static function (Dn $dn) use (&$authorized): void {
                $authorized = true;
            },
        );

        self::assertTrue($authorized);
    }

    private function contextWith(Control ...$controls): WriteContext
    {
        return new WriteContext(
            new SystemToken(),
            new ControlBag(...$controls),
        );
    }
}
