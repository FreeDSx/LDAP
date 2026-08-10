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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\Operation;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Operation\WriteEntryOperationHandler;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestInterface;
use LogicException;
use PHPUnit\Framework\TestCase;

final class WriteEntryOperationHandlerTest extends TestCase
{
    private WriteEntryOperationHandler $subject;

    private Entry $entry;

    protected function setUp(): void
    {
        $this->subject = new WriteEntryOperationHandler();
        $this->entry = new Entry(
            new Dn('cn=alice,dc=example,dc=com'),
            new Attribute('cn', 'alice'),
            new Attribute('mail', 'alice@example.com'),
            new Attribute('sn', 'Anderson'),
        );
    }

    public function test_an_update_does_not_modify_the_source_entry(): void
    {
        $command = new UpdateCommand(
            new Dn('cn=alice,dc=example,dc=com'),
            [Change::replace(new Attribute('sn'))],
        );

        $this->subject->apply($this->entry, $command);

        self::assertSame(
            ['Anderson'],
            $this->entry->get('sn')?->getValues(),
        );
    }

    public function test_an_update_adding_a_value_does_not_modify_the_source_entry(): void
    {
        $command = new UpdateCommand(
            new Dn('cn=alice,dc=example,dc=com'),
            [new Change(Change::TYPE_ADD, 'mail', 'second@example.com')],
        );

        $this->subject->apply($this->entry, $command);

        self::assertSame(
            ['alice@example.com'],
            $this->entry->get('mail')?->getValues(),
        );
    }

    public function test_a_move_deleting_the_old_rdn_does_not_modify_the_source_entry(): void
    {
        $command = new MoveCommand(
            new Dn('cn=alice,dc=example,dc=com'),
            new Rdn('cn', 'bob'),
            true,
            null,
        );

        $this->subject->apply($this->entry, $command);

        self::assertSame(
            ['alice'],
            $this->entry->get('cn')?->getValues(),
        );
        self::assertSame(
            'cn=alice,dc=example,dc=com',
            $this->entry->getDn()->toString(),
        );
    }

    public function test_an_update_returns_the_applied_changes_on_the_copy(): void
    {
        $command = new UpdateCommand(
            new Dn('cn=alice,dc=example,dc=com'),
            [new Change(Change::TYPE_ADD, 'mail', 'second@example.com')],
        );

        $result = $this->subject->apply($this->entry, $command);

        self::assertSame(
            ['alice@example.com', 'second@example.com'],
            $result->get('mail')?->getValues(),
        );
    }

    public function test_an_unsupported_command_is_rejected(): void
    {
        $this->expectException(LogicException::class);

        $this->subject->apply(
            $this->entry,
            new class implements WriteRequestInterface {},
        );
    }
}
