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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Write\Routing;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteSubtreeCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\Backend\Write\Routing\WriteRequestRouter;
use FreeDSx\Ldap\Server\Token\SystemToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class WriteRequestRouterTest extends TestCase
{
    private const DN = 'cn=foo,dc=example,dc=com';

    private WriteHandlerInterface&MockObject $writes;

    private WriteRequestRouter $subject;

    protected function setUp(): void
    {
        $this->writes = $this->createMock(WriteHandlerInterface::class);
        $this->subject = new WriteRequestRouter($this->writes);
    }

    public function test_a_delete_carrying_the_subtree_control_becomes_a_subtree_delete(): void
    {
        $this->expectCommand(DeleteSubtreeCommand::class);

        $this->subject->route(
            new DeleteRequest(self::DN),
            $this->contextWith(new Control(Control::OID_SUBTREE_DELETE)),
        );
    }

    public function test_a_delete_without_the_subtree_control_stays_a_delete(): void
    {
        $this->expectCommand(DeleteCommand::class);

        $this->subject->route(
            new DeleteRequest(self::DN),
            $this->contextWith(),
        );
    }

    public function test_the_subtree_control_on_another_operation_changes_nothing(): void
    {
        $this->expectCommand(AddCommand::class);

        $this->subject->route(
            new AddRequest(Entry::create(self::DN)),
            $this->contextWith(new Control(Control::OID_SUBTREE_DELETE)),
        );
    }

    /**
     * @param class-string $command
     */
    private function expectCommand(string $command): void
    {
        $this->writes
            ->expects(self::once())
            ->method('handle')
            ->with(self::isInstanceOf($command));
    }

    private function contextWith(Control ...$controls): WriteContext
    {
        return new WriteContext(
            new SystemToken(),
            new ControlBag(...$controls),
        );
    }
}
