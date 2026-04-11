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
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Operation\UpdateOperation;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use PHPUnit\Framework\TestCase;

final class UpdateOperationTest extends TestCase
{
    private UpdateOperation $subject;

    private Entry $entry;

    protected function setUp(): void
    {
        $this->subject = new UpdateOperation();
        $this->entry = new Entry(
            new Dn('cn=alice,dc=example,dc=com'),
            new Attribute('cn', 'alice'),
            new Attribute('mail', 'alice@example.com', 'a@b.com'),
            new Attribute('userPassword', '{SHA}secret'),
        );
    }

    public function test_type_add_appends_value_to_existing_attribute(): void
    {
        $command = new UpdateCommand(
            new Dn('cn=alice,dc=example,dc=com'),
            [new Change(Change::TYPE_ADD, 'mail', 'new@example.com')],
        );

        $result = $this->subject->execute($this->entry, $command);

        $mail = $result->get('mail');
        self::assertNotNull($mail);
        self::assertContains(
            'new@example.com',
            $mail->getValues()
        );
        self::assertContains(
            'alice@example.com',
            $mail->getValues()
        );
    }

    public function test_type_add_creates_attribute_when_absent(): void
    {
        $command = new UpdateCommand(
            new Dn('cn=alice,dc=example,dc=com'),
            [new Change(Change::TYPE_ADD, 'telephoneNumber', '+1 555 0100')],
        );

        $result = $this->subject->execute($this->entry, $command);

        self::assertSame(
            ['+1 555 0100'],
            $result->get('telephoneNumber')?->getValues()
        );
    }

    public function test_type_delete_with_no_values_removes_attribute(): void
    {
        $command = new UpdateCommand(
            new Dn('cn=alice,dc=example,dc=com'),
            [new Change(Change::TYPE_DELETE, 'userPassword')],
        );

        $result = $this->subject->execute($this->entry, $command);

        self::assertNull($result->get('userPassword'));
    }

    public function test_type_delete_with_values_removes_specific_values(): void
    {
        $command = new UpdateCommand(
            new Dn('cn=alice,dc=example,dc=com'),
            [new Change(Change::TYPE_DELETE, 'mail', 'a@b.com')],
        );

        $result = $this->subject->execute($this->entry, $command);

        $mail = $result->get('mail');

        self::assertNotNull($mail);
        self::assertNotContains(
            'a@b.com',
            $mail->getValues()
        );
        self::assertContains(
            'alice@example.com',
            $mail->getValues()
        );
    }

    public function test_type_replace_with_no_values_clears_attribute(): void
    {
        $command = new UpdateCommand(
            new Dn('cn=alice,dc=example,dc=com'),
            [new Change(Change::TYPE_REPLACE, 'userPassword')],
        );

        $result = $this->subject->execute($this->entry, $command);

        self::assertNull($result->get('userPassword'));
    }

    public function test_type_replace_sets_attribute_values(): void
    {
        $command = new UpdateCommand(
            new Dn('cn=alice,dc=example,dc=com'),
            [new Change(Change::TYPE_REPLACE, 'userPassword', 'newpassword')],
        );

        $result = $this->subject->execute($this->entry, $command);

        self::assertSame(
            ['newpassword'],
            $result->get('userPassword')?->getValues()
        );
    }

    public function test_multiple_changes_applied_in_order(): void
    {
        $command = new UpdateCommand(
            new Dn('cn=alice,dc=example,dc=com'),
            [
                new Change(Change::TYPE_REPLACE, 'mail', 'new@example.com'),
                new Change(Change::TYPE_ADD, 'mail', 'alice@example.com'),
            ],
        );

        $result = $this->subject->execute($this->entry, $command);

        $mail = $result->get('mail');

        self::assertNotNull($mail);
        self::assertContains(
            'new@example.com',
            $mail->getValues()
        );
        self::assertContains(
            'alice@example.com',
            $mail->getValues()
        );
    }

    public function test_returns_the_same_entry_instance(): void
    {
        $command = new UpdateCommand(
            new Dn('cn=alice,dc=example,dc=com'),
            [new Change(Change::TYPE_REPLACE, 'userPassword', 'newpassword')],
        );

        $result = $this->subject->execute($this->entry, $command);

        self::assertSame(
            $this->entry,
            $result
        );
    }

    public function test_type_add_throws_attribute_or_value_exists_for_duplicate_value(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ATTRIBUTE_OR_VALUE_EXISTS);

        $this->subject->execute($this->entry, new UpdateCommand(
            new Dn('cn=alice,dc=example,dc=com'),
            [new Change(Change::TYPE_ADD, 'mail', 'alice@example.com')],
        ));
    }

    public function test_type_delete_throws_no_such_attribute_for_missing_attribute(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_ATTRIBUTE);

        $this->subject->execute($this->entry, new UpdateCommand(
            new Dn('cn=alice,dc=example,dc=com'),
            [new Change(Change::TYPE_DELETE, 'telephoneNumber')],
        ));
    }

    public function test_type_delete_throws_no_such_attribute_for_missing_value(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_ATTRIBUTE);

        $this->subject->execute($this->entry, new UpdateCommand(
            new Dn('cn=alice,dc=example,dc=com'),
            [new Change(Change::TYPE_DELETE, 'mail', 'nobody@example.com')],
        ));
    }

    public function test_type_delete_whole_attribute_throws_not_allowed_on_rdn_for_rdn_attribute(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NOT_ALLOWED_ON_RDN);

        $this->subject->execute($this->entry, new UpdateCommand(
            new Dn('cn=alice,dc=example,dc=com'),
            [new Change(Change::TYPE_DELETE, 'cn')],
        ));
    }

    public function test_type_delete_specific_value_throws_not_allowed_on_rdn_for_rdn_value(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NOT_ALLOWED_ON_RDN);

        $this->subject->execute($this->entry, new UpdateCommand(
            new Dn('cn=alice,dc=example,dc=com'),
            [new Change(Change::TYPE_DELETE, 'cn', 'alice')],
        ));
    }

    public function test_type_delete_specific_value_allows_removing_non_rdn_value_from_rdn_attribute(): void
    {
        $entry = new Entry(
            new Dn('cn=alice,dc=example,dc=com'),
            new Attribute('cn', 'alice', 'alicia'),
        );

        $result = $this->subject->execute($entry, new UpdateCommand(
            new Dn('cn=alice,dc=example,dc=com'),
            [new Change(Change::TYPE_DELETE, 'cn', 'alicia')],
        ));

        $cn = $result->get('cn');

        self::assertNotNull($cn);
        self::assertNotContains(
            'alicia',
            $cn->getValues(),
        );
        self::assertContains(
            'alice',
            $cn->getValues(),
        );
    }

    public function test_type_replace_clear_throws_not_allowed_on_rdn_for_rdn_attribute(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NOT_ALLOWED_ON_RDN);

        $this->subject->execute($this->entry, new UpdateCommand(
            new Dn('cn=alice,dc=example,dc=com'),
            [new Change(Change::TYPE_REPLACE, 'cn')],
        ));
    }

    public function test_type_replace_throws_not_allowed_on_rdn_when_new_values_omit_rdn_value(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NOT_ALLOWED_ON_RDN);

        $this->subject->execute($this->entry, new UpdateCommand(
            new Dn('cn=alice,dc=example,dc=com'),
            [new Change(Change::TYPE_REPLACE, 'cn', 'alicia')],
        ));
    }

    public function test_type_replace_allows_replacing_rdn_attribute_when_rdn_value_is_retained(): void
    {
        $result = $this->subject->execute($this->entry, new UpdateCommand(
            new Dn('cn=alice,dc=example,dc=com'),
            [new Change(Change::TYPE_REPLACE, 'cn', 'alice', 'alicia')],
        ));

        $cn = $result->get('cn');

        self::assertNotNull($cn);
        self::assertContains(
            'alice',
            $cn->getValues(),
        );
        self::assertContains(
            'alicia',
            $cn->getValues(),
        );
    }
}
