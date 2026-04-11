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
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Operation\MoveOperation;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use PHPUnit\Framework\TestCase;

final class MoveOperationTest extends TestCase
{
    private MoveOperation $subject;

    private Entry $entry;

    protected function setUp(): void
    {
        $this->subject = new MoveOperation();
        $this->entry = new Entry(
            new Dn('cn=alice,dc=example,dc=com'),
            new Attribute('cn', 'alice'),
            new Attribute('mail', 'alice@example.com'),
        );
    }

    public function test_returned_entry_has_new_dn(): void
    {
        $command = new MoveCommand(
            dn: new Dn('cn=alice,dc=example,dc=com'),
            newRdn: new Rdn('cn', 'alicia'),
            deleteOldRdn: false,
            newParent: null,
        );

        $result = $this->subject->execute($this->entry, $command);

        self::assertSame(
            'cn=alicia,dc=example,dc=com',
            $result->getDn()->toString()
        );
    }

    public function test_delete_old_rdn_removes_old_rdn_value(): void
    {
        $command = new MoveCommand(
            dn: new Dn('cn=alice,dc=example,dc=com'),
            newRdn: new Rdn('cn', 'alicia'),
            deleteOldRdn: true,
            newParent: null,
        );

        $result = $this->subject->execute($this->entry, $command);
        $cn = $result->get('cn');

        self::assertNotNull($cn);
        self::assertNotContains(
            'alice',
            $cn->getValues()
        );
        self::assertContains(
            'alicia',
            $cn->getValues()
        );
    }

    public function test_preserve_old_rdn_keeps_old_rdn_value(): void
    {
        $command = new MoveCommand(
            dn: new Dn('cn=alice,dc=example,dc=com'),
            newRdn: new Rdn('cn', 'alicia'),
            deleteOldRdn: false,
            newParent: null,
        );

        $result = $this->subject->execute($this->entry, $command);

        $cn = $result->get('cn');

        self::assertNotNull($cn);
        self::assertContains(
            'alice',
            $cn->getValues()
        );
        self::assertContains(
            'alicia',
            $cn->getValues()
        );
    }

    public function test_new_rdn_attribute_added_when_absent(): void
    {
        $command = new MoveCommand(
            dn: new Dn('cn=alice,dc=example,dc=com'),
            newRdn: new Rdn('uid', 'alice'),
            deleteOldRdn: false,
            newParent: null,
        );

        $result = $this->subject->execute($this->entry, $command);

        self::assertSame(
            ['alice'],
            $result->get('uid')?->getValues()
        );
    }

    public function test_new_rdn_value_appended_when_attribute_exists_without_it(): void
    {
        $entry = new Entry(
            new Dn('cn=alice,dc=example,dc=com'),
            new Attribute('cn', 'alice'),
            new Attribute('uid', 'existing'),
        );

        $command = new MoveCommand(
            dn: new Dn('cn=alice,dc=example,dc=com'),
            newRdn: new Rdn('uid', 'alice'),
            deleteOldRdn: false,
            newParent: null,
        );

        $result = $this->subject->execute($entry, $command);
        $uid = $result->get('uid');

        self::assertNotNull($uid);
        self::assertContains(
            'existing',
            $uid->getValues()
        );
        self::assertContains(
            'alice',
            $uid->getValues()
        );
    }

    public function test_move_to_new_parent(): void
    {
        $command = new MoveCommand(
            dn: new Dn('cn=alice,dc=example,dc=com'),
            newRdn: new Rdn('cn', 'alice'),
            deleteOldRdn: false,
            newParent: new Dn('ou=People,dc=example,dc=com'),
        );

        $result = $this->subject->execute($this->entry, $command);

        self::assertSame(
            'cn=alice,ou=People,dc=example,dc=com',
            $result->getDn()->toString()
        );
    }

    public function test_rename_in_place_without_new_parent(): void
    {
        $command = new MoveCommand(
            dn: new Dn('cn=alice,dc=example,dc=com'),
            newRdn: new Rdn('cn', 'alicia'),
            deleteOldRdn: false,
            newParent: null,
        );

        $result = $this->subject->execute($this->entry, $command);

        self::assertSame(
            'cn=alicia,dc=example,dc=com',
            $result->getDn()->toString()
        );
    }

    public function test_original_attributes_are_preserved(): void
    {
        $command = new MoveCommand(
            dn: new Dn('cn=alice,dc=example,dc=com'),
            newRdn: new Rdn('cn', 'alicia'),
            deleteOldRdn: false,
            newParent: null,
        );

        $result = $this->subject->execute($this->entry, $command);

        self::assertSame(
            ['alice@example.com'],
            $result->get('mail')?->getValues()
        );
    }
}
