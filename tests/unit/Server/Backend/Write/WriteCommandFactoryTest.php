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
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteCommandFactory;
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
        $command = $this->subject->fromRequest(new AddRequest($entry));

        self::assertInstanceOf(AddCommand::class, $command);
        self::assertSame($entry, $command->entry);
    }

    public function test_it_creates_delete_command_from_delete_request(): void
    {
        $command = $this->subject->fromRequest(new DeleteRequest('cn=foo,dc=bar'));

        self::assertInstanceOf(DeleteCommand::class, $command);
        self::assertSame('cn=foo,dc=bar', $command->dn->toString());
    }

    public function test_it_creates_update_command_from_modify_request(): void
    {
        $changes = [Change::add('mail', 'foo@bar.com')];
        $command = $this->subject->fromRequest(new ModifyRequest('cn=foo,dc=bar', ...$changes));

        self::assertInstanceOf(UpdateCommand::class, $command);
        self::assertSame('cn=foo,dc=bar', $command->dn->toString());
        self::assertSame($changes, $command->changes);
    }

    public function test_it_creates_move_command_from_modify_dn_request(): void
    {
        $command = $this->subject->fromRequest(
            new ModifyDnRequest('cn=foo,dc=bar', 'cn=bar', true, 'ou=people,dc=bar')
        );

        self::assertInstanceOf(MoveCommand::class, $command);
        self::assertSame('cn=foo,dc=bar', $command->dn->toString());
        self::assertSame('cn=bar', $command->newRdn->toString());
        self::assertTrue($command->deleteOldRdn);
        self::assertSame('ou=people,dc=bar', $command->newParent?->toString());
    }

    public function test_it_throws_for_unsupported_request(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OPERATION);

        $this->subject->fromRequest(new AbandonRequest(1));
    }
}
