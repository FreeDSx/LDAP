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
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Definition\ObjectClassOid;
use FreeDSx\Ldap\Search\Filters;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

/**
 * End-to-end coverage of the RFC 3672 schema, under Strict validation.
 */
final class LdapSubentrySchemaTest extends ServerTestCase
{
    private const SPECIFICATION = '{ base "ou=People" }';

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

    public function test_a_subentry_can_be_added_and_read_back(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=policy-area,dc=foo,dc=bar',
            [
                'cn' => 'policy-area',
                'objectClass' => ObjectClassOid::NAME_SUBENTRY,
                AttributeTypeOid::NAME_SUBTREE_SPECIFICATION => self::SPECIFICATION,
            ],
        ));

        $entries = $this->ldapClient()->search(
            Operations::search(
                Filters::present('objectClass'),
                AttributeTypeOid::NAME_SUBTREE_SPECIFICATION,
            )
                ->base('cn=policy-area,dc=foo,dc=bar')
                ->useBaseScope(),
        );

        self::assertCount(
            1,
            $entries,
        );
        self::assertSame(
            self::SPECIFICATION,
            $entries->first()?->get(AttributeTypeOid::NAME_SUBTREE_SPECIFICATION)?->firstValue(),
        );
    }

    public function test_an_entry_may_carry_the_administrative_role_attribute(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'ou=Admin-Point,dc=foo,dc=bar',
            [
                'ou' => 'Admin-Point',
                'objectClass' => 'organizationalUnit',
                AttributeTypeOid::NAME_ADMINISTRATIVE_ROLE => '2.5.23.4',
            ],
        ));

        $entries = $this->ldapClient()->search(
            Operations::search(
                Filters::present('objectClass'),
                AttributeTypeOid::NAME_ADMINISTRATIVE_ROLE,
            )
                ->base('ou=Admin-Point,dc=foo,dc=bar')
                ->useBaseScope(),
        );

        self::assertSame(
            '2.5.23.4',
            $entries->first()?->get(AttributeTypeOid::NAME_ADMINISTRATIVE_ROLE)?->firstValue(),
        );
    }

    /**
     * It is STRUCTURAL with SUP top, so it cannot be combined with another structural class.
     */
    public function test_a_subentry_combined_with_another_structural_class_is_rejected(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->ldapClient()->create(Entry::fromArray(
            'cn=subentry-person,dc=foo,dc=bar',
            [
                'cn' => 'subentry-person',
                'sn' => 'Smith',
                'objectClass' => [ObjectClassOid::NAME_SUBENTRY, 'person'],
                AttributeTypeOid::NAME_SUBTREE_SPECIFICATION => self::SPECIFICATION,
            ],
        ));
    }

    public function test_a_subentry_without_a_subtree_specification_is_rejected(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->ldapClient()->create(Entry::fromArray(
            'cn=no-specification,dc=foo,dc=bar',
            [
                'cn' => 'no-specification',
                'objectClass' => ObjectClassOid::NAME_SUBENTRY,
            ],
        ));
    }
}
