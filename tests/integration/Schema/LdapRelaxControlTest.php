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

use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

/**
 * End-to-end Relax Rules control behaviour; the shared server runs Strict validation and grants relax to
 * authenticated identities.
 */
final class LdapRelaxControlTest extends ServerTestCase
{
    private const VALUE_LIMIT = 20;

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldap-backend-storage',
            'tcp',
            [
                '--validation-mode=strict',
                '--allow-relax',
                '--max-attribute-values=' . self::VALUE_LIMIT,
            ],
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

    public function test_a_relaxed_add_keeps_the_operational_attributes_it_supplies(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(
            Entry::fromArray(
                'cn=relax-add,dc=foo,dc=bar',
                [
                    'cn' => 'relax-add',
                    'sn' => 'Drift',
                    'objectClass' => 'person',
                    'createTimestamp' => '20200101000000Z',
                    'modifyTimestamp' => '20200102000000Z',
                    'creatorsName' => 'cn=jane,dc=foo,dc=bar',
                    'modifiersName' => 'cn=joe,dc=foo,dc=bar',
                    'entryUUID' => '597ae2f6-16a6-1027-98f4-d28b5365dc14',
                ],
            ),
            Controls::relaxRules(),
        );

        self::assertSame(
            [
                'createTimestamp' => '20200101000000Z',
                'modifyTimestamp' => '20200102000000Z',
                'creatorsName' => 'cn=jane,dc=foo,dc=bar',
                'modifiersName' => 'cn=joe,dc=foo,dc=bar',
                'entryUUID' => '597ae2f6-16a6-1027-98f4-d28b5365dc14',
            ],
            $this->operationalValuesOf('cn=relax-add,dc=foo,dc=bar'),
        );
    }

    public function test_a_relaxed_modify_keeps_the_modify_bookkeeping_it_supplies(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=relax-modify-stamp,dc=foo,dc=bar',
            [
                'cn' => 'relax-modify-stamp',
                'sn' => 'Drift',
                'objectClass' => 'person',
            ],
        ));

        $this->ldapClient()->send(
            Operations::modify(
                'cn=relax-modify-stamp,dc=foo,dc=bar',
                Change::replace(
                    'createTimestamp',
                    '20200101000000Z',
                ),
                Change::replace(
                    'modifyTimestamp',
                    '20200102000000Z',
                ),
                Change::replace(
                    'modifiersName',
                    'cn=joe,dc=foo,dc=bar',
                ),
            ),
            Controls::relaxRules(),
        );

        $values = $this->operationalValuesOf('cn=relax-modify-stamp,dc=foo,dc=bar');

        self::assertSame(
            ['20200101000000Z', '20200102000000Z', 'cn=joe,dc=foo,dc=bar'],
            [$values['createTimestamp'], $values['modifyTimestamp'], $values['modifiersName']],
        );
    }

    public function test_a_relaxed_add_refuses_a_create_timestamp_in_the_future(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->ldapClient()->create(
            Entry::fromArray(
                'cn=relax-future,dc=foo,dc=bar',
                [
                    'cn' => 'relax-future',
                    'sn' => 'Drift',
                    'objectClass' => 'person',
                    'createTimestamp' => '20990101000000Z',
                ],
            ),
            Controls::relaxRules(),
        );
    }

    public function test_a_relaxed_add_refuses_an_entry_uuid_another_entry_holds(): void
    {
        $this->authenticateAdmin();
        $held = $this->operationalValuesOf('cn=user,dc=foo,dc=bar')['entryUUID'];

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->ldapClient()->create(
            Entry::fromArray(
                'cn=relax-uuid-taken,dc=foo,dc=bar',
                [
                    'cn' => 'relax-uuid-taken',
                    'sn' => 'Drift',
                    'objectClass' => 'person',
                    'entryUUID' => (string) $held,
                ],
            ),
            Controls::relaxRules(),
        );
    }

    public function test_a_relaxed_modify_refuses_to_change_the_entry_uuid(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->ldapClient()->send(
            Operations::modify(
                'cn=user,dc=foo,dc=bar',
                Change::replace(
                    'entryUUID',
                    '6f1c5a4e-2b8d-4c3a-9e7f-0a1b2c3d4e5f',
                ),
            ),
            Controls::relaxRules(),
        );
    }

    public function test_relax_control_does_not_allow_an_unlisted_no_user_modification_attribute(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->ldapClient()->create(
            Entry::fromArray(
                'cn=relax-structural,dc=foo,dc=bar',
                [
                    'cn' => 'relax-structural',
                    'sn' => 'Drift',
                    'objectClass' => 'person',
                    'structuralObjectClass' => 'device',
                ],
            ),
            Controls::relaxRules(),
        );
    }

    public function test_the_no_user_modification_rule_holds_on_add_without_the_control(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->ldapClient()->create(Entry::fromArray(
            'cn=relax-add-refused,dc=foo,dc=bar',
            [
                'cn' => 'relax-add-refused',
                'sn' => 'Drift',
                'objectClass' => 'person',
                'createTimestamp' => '20200101000000Z',
            ],
        ));
    }

    public function test_relax_control_does_not_allow_an_attribute_no_object_class_permits(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->ldapClient()->create(
            Entry::fromArray(
                'cn=relax-disallowed,dc=foo,dc=bar',
                [
                    'cn' => 'relax-disallowed',
                    'sn' => 'Drift',
                    'objectClass' => 'person',
                    'mail' => 'relax-disallowed@foo.bar',
                ],
            ),
            Controls::relaxRules(),
        );
    }

    public function test_a_relaxed_structural_class_change_must_still_leave_a_conforming_entry(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=relax-to-device,dc=foo,dc=bar',
            [
                'cn' => 'relax-to-device',
                'sn' => 'Drift',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->ldapClient()->send(
            Operations::modify(
                'cn=relax-to-device,dc=foo,dc=bar',
                Change::replace(
                    'objectClass',
                    'device',
                ),
            ),
            Controls::relaxRules(),
        );
    }

    public function test_relax_control_does_not_allow_equivalent_values(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ATTRIBUTE_OR_VALUE_EXISTS);

        $this->ldapClient()->create(
            Entry::fromArray(
                'cn=relax-equivalent,dc=foo,dc=bar',
                [
                    'cn' => 'relax-equivalent',
                    'sn' => 'Drift',
                    'objectClass' => 'person',
                    'description' => ['same', 'SAME'],
                ],
            ),
            Controls::relaxRules(),
        );
    }

    public function test_a_relaxed_violation_does_not_hide_the_attribute_value_limit(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $this->ldapClient()->create(
            Entry::fromArray(
                'cn=relax-hidden-limit,dc=foo,dc=bar',
                [
                    'cn' => 'relax-hidden-limit',
                    'sn' => 'Drift',
                    'objectClass' => 'person',
                    'createTimestamp' => '20200101000000Z',
                    'description' => array_map(
                        static fn(int $i): string => "value {$i}",
                        range(1, self::VALUE_LIMIT + 1),
                    ),
                ],
            ),
            Controls::relaxRules(),
        );
    }

    public function test_same_add_is_rejected_under_strict_without_the_control(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->ldapClient()->create(Entry::fromArray(
            'cn=relax-rejected,dc=foo,dc=bar',
            [
                'cn' => 'relax-rejected',
                'sn' => 'Drift',
                'objectClass' => 'person',
                'mail' => 'relax-rejected@foo.bar',
            ],
        ));
    }

    public function test_relax_control_does_not_bypass_invalid_syntax_behind_a_relaxed_violation(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        // entryUUID is NO-USER-MODIFICATION, which relax waives, but its value is still malformed.
        $this->ldapClient()->create(
            Entry::fromArray(
                'cn=relax-bad-uuid,dc=foo,dc=bar',
                [
                    'cn' => 'relax-bad-uuid',
                    'sn' => 'Drift',
                    'objectClass' => 'person',
                    'entryUUID' => 'not-a-uuid',
                ],
            ),
            Controls::relaxRules(),
        );
    }

    public function test_relax_control_does_not_bypass_invalid_attribute_syntax(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->ldapClient()->create(
            Entry::fromArray(
                'cn=relax-bad-syntax,dc=foo,dc=bar',
                [
                    'cn' => 'relax-bad-syntax',
                    'sn' => 'Drift',
                    'objectClass' => 'person',
                    'seeAlso' => 'not a dn',
                ],
            ),
            Controls::relaxRules(),
        );
    }

    public function test_a_relaxed_structural_class_replace_restamps_the_structural_object_class(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=relax-replace-class,dc=foo,dc=bar',
            [
                'cn' => 'relax-replace-class',
                'sn' => 'Drift',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        $this->ldapClient()->send(
            Operations::modify(
                'cn=relax-replace-class,dc=foo,dc=bar',
                Change::replace(
                    'objectClass',
                    'organizationalPerson',
                ),
            ),
            Controls::relaxRules(),
        );

        self::assertSame(
            'organizationalPerson',
            $this->structuralObjectClassOf('cn=relax-replace-class,dc=foo,dc=bar'),
        );
    }

    public function test_a_relaxed_addition_of_a_more_specific_structural_class_restamps_it(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=relax-add-class,dc=foo,dc=bar',
            [
                'cn' => 'relax-add-class',
                'sn' => 'Drift',
                'objectClass' => 'person',
            ],
        ));

        $this->ldapClient()->send(
            Operations::modify(
                'cn=relax-add-class,dc=foo,dc=bar',
                Change::add(
                    'objectClass',
                    'inetOrgPerson',
                ),
            ),
            Controls::relaxRules(),
        );

        self::assertSame(
            'inetOrgPerson',
            $this->structuralObjectClassOf('cn=relax-add-class,dc=foo,dc=bar'),
        );
    }

    public function test_relax_control_does_not_bypass_the_attribute_value_limit(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $this->ldapClient()->create(
            Entry::fromArray(
                'cn=relax-too-many,dc=foo,dc=bar',
                [
                    'cn' => 'relax-too-many',
                    'sn' => 'Drift',
                    'objectClass' => 'person',
                    'description' => array_map(
                        static fn(int $i): string => "value {$i}",
                        range(1, self::VALUE_LIMIT + 1),
                    ),
                ],
            ),
            Controls::relaxRules(),
        );
    }

    /**
     * @return array<string, ?string>
     */
    private function operationalValuesOf(string $dn): array
    {
        $names = ['createTimestamp', 'modifyTimestamp', 'creatorsName', 'modifiersName', 'entryUUID'];
        $entry = $this->ldapClient()->search(
            Operations::search(
                Filters::present('objectClass'),
                ...$names,
            )
                ->base($dn)
                ->useBaseScope(),
        )->first();

        $values = [];
        foreach ($names as $name) {
            $values[$name] = $entry?->get($name)?->firstValue();
        }

        return $values;
    }

    private function structuralObjectClassOf(string $dn): ?string
    {
        return $this->ldapClient()->search(
            Operations::search(
                Filters::present('objectClass'),
                'structuralObjectClass',
            )
                ->base($dn)
                ->useBaseScope(),
        )->first()?->get('structuralObjectClass')?->firstValue();
    }
}
