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
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteSubtreeCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\Routing\WriteCommandFactory;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Token\AnonToken;
use PHPUnit\Framework\TestCase;

final class WriteCommandFactoryTest extends TestCase
{
    private WriteCommandFactory $subject;

    protected function setUp(): void
    {
        $this->subject = new WriteCommandFactory();
    }

    public function test_it_creates_add_command_from_add_request(): void
    {
        $entry = Entry::create('cn=foo,dc=bar');
        $command = $this->subject->fromRequest(
            new AddRequest($entry),
            $this->context(),
        );

        self::assertInstanceOf(AddCommand::class, $command);
        self::assertSame($entry, $command->entry);
    }

    public function test_it_creates_delete_command_from_delete_request(): void
    {
        $command = $this->subject->fromRequest(
            new DeleteRequest('cn=foo,dc=bar'),
            $this->context(),
        );

        self::assertInstanceOf(DeleteCommand::class, $command);
        self::assertSame('cn=foo,dc=bar', $command->dn->toString());
    }

    public function test_the_subtree_control_makes_a_delete_a_subtree_delete(): void
    {
        $command = $this->subject->fromRequest(
            new DeleteRequest('cn=foo,dc=bar'),
            $this->context(new Control(Control::OID_SUBTREE_DELETE)),
        );

        self::assertInstanceOf(DeleteSubtreeCommand::class, $command);
        self::assertSame('cn=foo,dc=bar', $command->dn->toString());
    }

    public function test_the_subtree_control_on_another_operation_changes_nothing(): void
    {
        $command = $this->subject->fromRequest(
            new AddRequest(Entry::create('cn=foo,dc=bar')),
            $this->context(new Control(Control::OID_SUBTREE_DELETE)),
        );

        self::assertInstanceOf(AddCommand::class, $command);
    }

    public function test_it_creates_update_command_from_modify_request(): void
    {
        $changes = [Change::add('mail', 'foo@bar.com')];
        $command = $this->subject->fromRequest(
            new ModifyRequest('cn=foo,dc=bar', ...$changes),
            $this->context(),
        );

        self::assertInstanceOf(UpdateCommand::class, $command);
        self::assertSame('cn=foo,dc=bar', $command->dn->toString());
        self::assertSame($changes, $command->changes);
    }

    public function test_it_creates_move_command_from_modify_dn_request(): void
    {
        $command = $this->subject->fromRequest(
            new ModifyDnRequest('cn=foo,dc=bar', 'cn=bar', true, 'ou=people,dc=bar'),
            $this->context(),
        );

        self::assertInstanceOf(MoveCommand::class, $command);
        self::assertSame('cn=foo,dc=bar', $command->dn->toString());
        self::assertSame('cn=bar', $command->newRdn->toString());
        self::assertTrue($command->deleteOldRdn);
        self::assertSame('ou=people,dc=bar', $command->newParent?->toString());
    }

    public function test_it_rejects_a_new_rdn_that_is_not_utf8(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::INVALID_DN_SYNTAX);

        $this->subject->fromRequest(
            new ModifyDnRequest(
                'cn=foo,dc=bar',
                "cn=\xFF\xFE",
                true,
            ),
            $this->context(),
        );
    }

    public function test_it_rejects_an_added_dn_whose_canonical_form_is_not_utf8(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::INVALID_DN_SYNTAX);

        $this->subject->fromRequest(
            new AddRequest(Entry::fromArray('userPassword=\FF,dc=bar', ['objectClass' => 'top'])),
            $this->context(),
        );
    }

    public function test_it_rejects_a_new_rdn_whose_canonical_form_is_not_utf8(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::INVALID_DN_SYNTAX);

        $this->subject->fromRequest(
            new ModifyDnRequest(
                'cn=foo,dc=bar',
                'userPassword=\FF',
                true,
            ),
            $this->context(),
        );
    }

    public function test_it_holds_a_write_to_the_generated_entry_guard(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $this->subject->fromRequest(
            new DeleteRequest(''),
            $this->context(new Control(Control::OID_SUBTREE_DELETE)),
        );
    }

    public function test_it_throws_for_unsupported_request(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OPERATION);

        $this->subject->fromRequest(
            new AbandonRequest(1),
            $this->context(),
        );
    }

    private function context(Control ...$controls): WriteContext
    {
        return new WriteContext(
            new AnonToken(),
            new ControlBag(...$controls),
        );
    }
}
