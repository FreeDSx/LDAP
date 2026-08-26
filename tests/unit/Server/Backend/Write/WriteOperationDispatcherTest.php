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
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\ComputeUpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteSubtreeCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\Operation\AddEntryHandler;
use FreeDSx\Ldap\Server\Backend\Write\Operation\DeleteEntryHandler;
use FreeDSx\Ldap\Server\Backend\Write\Operation\ComputeUpdateHandler;
use FreeDSx\Ldap\Server\Backend\Write\Operation\DeleteSubtreeHandler;
use FreeDSx\Ldap\Server\Backend\Write\Operation\MoveEntryHandler;
use FreeDSx\Ldap\Server\Backend\Write\Operation\UpdateEntryHandler;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestInterface;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class WriteOperationDispatcherTest extends TestCase
{
    use ServerContainerTrait;

    private AddEntryHandler&MockObject $add;

    private DeleteEntryHandler&MockObject $delete;

    private DeleteSubtreeHandler&MockObject $deleteSubtree;

    private UpdateEntryHandler&MockObject $update;

    private ComputeUpdateHandler&MockObject $computeUpdate;

    private MoveEntryHandler&MockObject $move;

    private WriteOperationDispatcher $subject;

    private WriteContext $context;

    protected function setUp(): void
    {
        $this->add = $this->createMock(AddEntryHandler::class);
        $this->delete = $this->createMock(DeleteEntryHandler::class);
        $this->deleteSubtree = $this->createMock(DeleteSubtreeHandler::class);
        $this->update = $this->createMock(UpdateEntryHandler::class);
        $this->computeUpdate = $this->createMock(ComputeUpdateHandler::class);
        $this->move = $this->createMock(MoveEntryHandler::class);
        $this->context = new WriteContext(
            new AnonToken(),
            new ControlBag(),
        );
        // Resolved from the container, so the command-to-handler mapping under test is the one the server wires.
        $this->subject = $this->containerFor(
            new InMemoryStorage(),
            sharedInstances: [
                AddEntryHandler::class => $this->add,
                DeleteEntryHandler::class => $this->delete,
                DeleteSubtreeHandler::class => $this->deleteSubtree,
                UpdateEntryHandler::class => $this->update,
                ComputeUpdateHandler::class => $this->computeUpdate,
                MoveEntryHandler::class => $this->move,
            ],
        )->get(WriteOperationDispatcher::class);
    }

    public function test_an_add_reaches_the_add_handler(): void
    {
        $command = new AddCommand(new Entry(
            new Dn('cn=a,dc=example,dc=com'),
            new Attribute('cn', 'a'),
        ));

        $this->add
            ->expects(self::once())
            ->method('handle')
            ->with($command, $this->context);
        $this->delete->expects(self::never())->method('handle');

        $this->subject->handle(
            $command,
            $this->context,
        );
    }

    public function test_a_delete_reaches_the_delete_handler(): void
    {
        $command = new DeleteCommand(new Dn('cn=a,dc=example,dc=com'));

        $this->delete
            ->expects(self::once())
            ->method('handle')
            ->with($command, $this->context);
        $this->add->expects(self::never())->method('handle');

        $this->subject->handle(
            $command,
            $this->context,
        );
    }

    public function test_a_subtree_delete_reaches_the_subtree_handler(): void
    {
        $command = new DeleteSubtreeCommand(new Dn('ou=people,dc=example,dc=com'));

        $this->deleteSubtree
            ->expects(self::once())
            ->method('handle')
            ->with($command, $this->context);
        $this->delete->expects(self::never())->method('handle');

        $this->subject->handle(
            $command,
            $this->context,
        );
    }

    public function test_an_update_reaches_the_update_handler(): void
    {
        $command = new UpdateCommand(
            new Dn('cn=a,dc=example,dc=com'),
            [],
        );

        $this->update
            ->expects(self::once())
            ->method('handle')
            ->with($command, $this->context);
        $this->move->expects(self::never())->method('handle');

        $this->subject->handle(
            $command,
            $this->context,
        );
    }

    public function test_a_compute_update_reaches_the_compute_handler(): void
    {
        $command = new ComputeUpdateCommand(
            new Dn('cn=a,dc=example,dc=com'),
            static fn(Entry $entry): array => [],
        );

        $this->computeUpdate
            ->expects(self::once())
            ->method('handle')
            ->with($command, $this->context);
        $this->update->expects(self::never())->method('handle');

        $this->subject->handle(
            $command,
            $this->context,
        );
    }

    public function test_a_move_reaches_the_move_handler(): void
    {
        $command = new MoveCommand(
            new Dn('cn=a,dc=example,dc=com'),
            new Rdn('cn', 'b'),
            true,
            null,
        );

        $this->move
            ->expects(self::once())
            ->method('handle')
            ->with($command, $this->context);
        $this->update->expects(self::never())->method('handle');

        $this->subject->handle(
            $command,
            $this->context,
        );
    }

    public function test_a_command_with_no_operation_is_refused(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $this->subject->handle(
            $this->createMock(WriteRequestInterface::class),
            $this->context,
        );
    }
}
