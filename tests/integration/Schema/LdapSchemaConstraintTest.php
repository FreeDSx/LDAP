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

namespace Tests\Integration\FreeDSx\Ldap\Schema;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

/**
 * End-to-end enforcement of what the shipped schema declares, under Strict validation.
 */
final class LdapSchemaConstraintTest extends ServerTestCase
{
    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldap-backend-storage',
            'tcp',
            ['--validation-mode=strict'],
        );
    }

    public static function tearDownAfterClass(): void
    {
        parent::tearDownAfterClass();
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        $this->setServerMode('ldap-backend-storage');

        parent::setUp();
    }

    public function test_add_with_invalid_attribute_syntax_is_rejected(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->ldapClient()->create(Entry::fromArray(
            'cn=bad-syntax,dc=foo,dc=bar',
            [
                'cn' => 'bad-syntax',
                'sn' => 'Smith',
                'objectClass' => 'person',
                'seeAlso' => 'not a dn',
            ],
        ));
    }

    public function test_add_with_two_unrelated_structural_classes_is_rejected(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->ldapClient()->create(Entry::fromArray(
            'cn=two-structural,dc=foo,dc=bar',
            [
                'cn' => 'two-structural',
                'sn' => 'Smith',
                'ou' => 'People',
                'objectClass' => ['person', 'organizationalUnit'],
            ],
        ));
    }

    public function test_add_missing_a_required_attribute_of_a_built_in_class_is_rejected(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        // 'sn' is MUST on the 'person' class.
        $this->ldapClient()->create(Entry::fromArray(
            'cn=no-surname,dc=foo,dc=bar',
            [
                'cn' => 'no-surname',
                'objectClass' => 'person',
            ],
        ));
    }

    public function test_modify_adding_an_attribute_the_class_does_not_permit_is_rejected(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->ldapClient()->create(Entry::fromArray(
            'cn=strict-modify,dc=foo,dc=bar',
            [
                'cn' => 'strict-modify',
                'sn' => 'Smith',
                'objectClass' => 'person',
            ],
        ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        // 'mail' is neither MUST nor MAY on 'person'.
        $entry = Entry::fromArray('cn=strict-modify,dc=foo,dc=bar');
        $entry->set('mail', 'strict-modify@foo.bar');
        $this->ldapClient()->update($entry);
    }

    public function test_add_with_two_values_for_a_single_valued_attribute_is_rejected(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        // 'displayName' is SINGLE-VALUE.
        $this->ldapClient()->create(Entry::fromArray(
            'cn=two-display-names,dc=foo,dc=bar',
            [
                'cn' => 'two-display-names',
                'sn' => 'Smith',
                'objectClass' => 'inetOrgPerson',
                'displayName' => ['First', 'Second'],
            ],
        ));
    }

    public function test_modify_adding_a_second_value_to_a_single_valued_attribute_is_rejected(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->ldapClient()->create(Entry::fromArray(
            'cn=single-value-modify,dc=foo,dc=bar',
            [
                'cn' => 'single-value-modify',
                'sn' => 'Smith',
                'objectClass' => 'inetOrgPerson',
                'displayName' => 'First',
            ],
        ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $entry = Entry::fromArray('cn=single-value-modify,dc=foo,dc=bar');
        $entry->add('displayName', 'Second');
        $this->ldapClient()->update($entry);
    }

    public function test_add_writing_a_no_user_modification_attribute_is_rejected(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        // 'createTimestamp' is NO-USER-MODIFICATION; the server maintains it.
        $this->ldapClient()->create(Entry::fromArray(
            'cn=client-timestamp,dc=foo,dc=bar',
            [
                'cn' => 'client-timestamp',
                'sn' => 'Smith',
                'objectClass' => 'person',
                'createTimestamp' => '20200101000000Z',
            ],
        ));
    }

    public function test_modify_writing_a_no_user_modification_attribute_is_rejected(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->ldapClient()->create(Entry::fromArray(
            'cn=operational-modify,dc=foo,dc=bar',
            [
                'cn' => 'operational-modify',
                'sn' => 'Smith',
                'objectClass' => 'person',
            ],
        ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $entry = Entry::fromArray('cn=operational-modify,dc=foo,dc=bar');
        $entry->set('modifiersName', 'cn=someone,dc=foo,dc=bar');
        $this->ldapClient()->update($entry);
    }

    public function test_add_with_a_non_numeric_value_for_an_integer_attribute_is_rejected(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        // 'gidNumber' declares the INTEGER syntax.
        $this->ldapClient()->create(Entry::fromArray(
            'cn=bad-gid,dc=foo,dc=bar',
            [
                'cn' => 'bad-gid',
                'objectClass' => 'posixGroup',
                'gidNumber' => 'not-a-number',
            ],
        ));
    }

    public function test_add_with_a_non_boolean_value_for_a_boolean_attribute_is_rejected(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        // 'pwdLockout' declares the BOOLEAN syntax, which permits only TRUE or FALSE.
        $this->ldapClient()->create(Entry::fromArray(
            'cn=bad-boolean,dc=foo,dc=bar',
            [
                'cn' => 'bad-boolean',
                'sn' => 'Smith',
                'objectClass' => ['person', 'pwdPolicy'],
                'pwdAttribute' => 'userPassword',
                'pwdLockout' => 'maybe',
            ],
        ));
    }

    public function test_the_nis_schema_is_usable_end_to_end(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->ldapClient()->create(Entry::fromArray(
            'cn=admins,dc=foo,dc=bar',
            [
                'cn' => 'admins',
                'objectClass' => 'posixGroup',
                'gidNumber' => '5000',
                'memberUid' => ['alice', 'bob'],
            ],
        ));

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('gidNumber', '5000'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $entries);
        self::assertSame(
            'admins',
            $entries->first()?->get('cn')?->firstValue(),
        );
    }

    public function test_a_posix_group_missing_its_required_gid_is_rejected(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        // 'gidNumber' is MUST on 'posixGroup'.
        $this->ldapClient()->create(Entry::fromArray(
            'cn=no-gid,dc=foo,dc=bar',
            [
                'cn' => 'no-gid',
                'objectClass' => 'posixGroup',
            ],
        ));
    }
}
