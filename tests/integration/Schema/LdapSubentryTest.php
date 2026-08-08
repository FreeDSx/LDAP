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
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Definition\ObjectClassOid;
use FreeDSx\Ldap\Search\Filters;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

/**
 * End-to-end RFC 3672 subentry behavior. For search behavior see {@see LdapSubentryVisibilityTest}.
 */
final class LdapSubentryTest extends ServerTestCase
{
    private const ADMIN_ROLE = '2.5.23.4';

    private const MALFORMED = '{ base "ou=people"';

    private const EVERY_COMPONENT = '{ base "ou=people", specificExclusions { chopBefore:"cn=x", chopAfter:"ou=y" }, '
        . 'minimum 1, maximum 4, specificationFilter and:{ item:person, not:item:device } }';

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
        $this->makeParent('read-back', isAdministrative: true);

        $this->ldapClient()->create($this->subentry(
            'cn=policy,ou=read-back,dc=foo,dc=bar',
            self::EVERY_COMPONENT,
        ));

        self::assertSame(
            self::EVERY_COMPONENT,
            $this->readSpecification('cn=policy,ou=read-back,dc=foo,dc=bar'),
        );
    }

    public function test_an_entry_may_carry_the_administrative_role_attribute(): void
    {
        $this->authenticateAdmin();
        $this->makeParent('role-holder', isAdministrative: true);

        $entries = $this->ldapClient()->search(
            Operations::search(
                Filters::present('objectClass'),
                AttributeTypeOid::NAME_ADMINISTRATIVE_ROLE,
            )
                ->base('ou=role-holder,dc=foo,dc=bar')
                ->useBaseScope(),
        );

        self::assertSame(
            self::ADMIN_ROLE,
            $entries->first()?->get(AttributeTypeOid::NAME_ADMINISTRATIVE_ROLE)?->firstValue(),
        );
    }

    /**
     * It is STRUCTURAL with SUP top, so it cannot be combined with another structural class.
     */
    public function test_a_subentry_combined_with_another_structural_class_is_rejected(): void
    {
        $this->authenticateAdmin();
        $this->makeParent('mixed-class', isAdministrative: true);

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->ldapClient()->create(Entry::fromArray(
            'cn=mixed,ou=mixed-class,dc=foo,dc=bar',
            [
                'cn' => 'mixed',
                'sn' => 'Smith',
                'objectClass' => [ObjectClassOid::NAME_SUBENTRY, 'person'],
                AttributeTypeOid::NAME_SUBTREE_SPECIFICATION => '{ }',
            ],
        ));
    }

    public function test_a_subentry_without_a_subtree_specification_is_rejected(): void
    {
        $this->authenticateAdmin();
        $this->makeParent('no-spec', isAdministrative: true);

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->ldapClient()->create(Entry::fromArray(
            'cn=bare,ou=no-spec,dc=foo,dc=bar',
            [
                'cn' => 'bare',
                'objectClass' => ObjectClassOid::NAME_SUBENTRY,
            ],
        ));
    }

    public function test_an_empty_specification_is_accepted(): void
    {
        $this->authenticateAdmin();
        $this->makeParent('empty-spec', isAdministrative: true);

        $this->ldapClient()->create($this->subentry(
            'cn=empty,ou=empty-spec,dc=foo,dc=bar',
            '{ }',
        ));

        self::assertSame(
            '{ }',
            $this->readSpecification('cn=empty,ou=empty-spec,dc=foo,dc=bar'),
        );
    }

    /**
     * Neither Lenient validation nor relax may excuse an unparseable value, so both run on one server.
     */
    public function test_a_malformed_specification_is_rejected_under_lenient_validation(): void
    {
        $this->startLenientRelaxServer();
        $this->authenticateAdmin();
        $this->makeParent('bad-lenient', isAdministrative: true);

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->ldapClient()->create($this->subentry(
            'cn=bad,ou=bad-lenient,dc=foo,dc=bar',
            self::MALFORMED,
        ));
    }

    public function test_a_malformed_specification_is_rejected_even_with_the_relax_control(): void
    {
        $this->startLenientRelaxServer();
        $this->authenticateAdmin();
        $this->makeParent('bad-relaxed', isAdministrative: true);

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->ldapClient()->create(
            $this->subentry(
                'cn=bad,ou=bad-relaxed,dc=foo,dc=bar',
                self::MALFORMED,
            ),
            Controls::relaxRules(),
        );
    }

    public function test_a_subentry_under_a_plain_parent_is_rejected(): void
    {
        $this->authenticateAdmin();
        $this->makeParent('plain-add', isAdministrative: false);

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $this->ldapClient()->create($this->subentry(
            'cn=under-plain,ou=plain-add,dc=foo,dc=bar',
            '{ }',
        ));
    }

    /**
     * The placement rule concerns subentries only.
     */
    public function test_a_plain_entry_under_a_plain_parent_is_accepted(): void
    {
        $this->authenticateAdmin();
        $this->makeParent('plain-ok', isAdministrative: false);

        $this->ldapClient()->create(Entry::fromArray(
            'cn=plain-child,ou=plain-ok,dc=foo,dc=bar',
            [
                'cn' => 'plain-child',
                'sn' => 'Child',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        self::assertNotNull($this->ldapClient()->read('cn=plain-child,ou=plain-ok,dc=foo,dc=bar'));
    }

    public function test_moving_a_subentry_under_a_plain_parent_is_rejected(): void
    {
        $this->authenticateAdmin();
        $this->makeParent('move-from', isAdministrative: true);
        $this->makeParent('move-to-plain', isAdministrative: false);
        $this->ldapClient()->create($this->subentry(
            'cn=mover,ou=move-from,dc=foo,dc=bar',
            '{ }',
        ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $this->ldapClient()->move(
            'cn=mover,ou=move-from,dc=foo,dc=bar',
            'ou=move-to-plain,dc=foo,dc=bar',
        );
    }

    public function test_moving_a_subentry_under_an_administrative_point_is_accepted(): void
    {
        $this->authenticateAdmin();
        $this->makeParent('move-src', isAdministrative: true);
        $this->makeParent('move-dst', isAdministrative: true);
        $this->ldapClient()->create($this->subentry(
            'cn=good-mover,ou=move-src,dc=foo,dc=bar',
            '{ }',
        ));

        $this->ldapClient()->move(
            'cn=good-mover,ou=move-src,dc=foo,dc=bar',
            'ou=move-dst,dc=foo,dc=bar',
        );

        self::assertNotNull($this->ldapClient()->read('cn=good-mover,ou=move-dst,dc=foo,dc=bar'));
    }

    /**
     * Removing it would leave the subentries below it silently inert.
     */
    public function test_removing_the_administrative_role_while_subentries_remain_is_rejected(): void
    {
        $this->authenticateAdmin();
        $this->makeParent('held-area', isAdministrative: true);
        $this->ldapClient()->create($this->subentry(
            'cn=holder,ou=held-area,dc=foo,dc=bar',
            '{ }',
        ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $this->ldapClient()->update(
            Entry::fromArray('ou=held-area,dc=foo,dc=bar')
                ->reset(AttributeTypeOid::NAME_ADMINISTRATIVE_ROLE),
        );
    }

    public function test_removing_the_administrative_role_with_no_subentries_is_accepted(): void
    {
        $this->authenticateAdmin();
        $this->makeParent('empty-area', isAdministrative: true);

        $this->ldapClient()->update(
            Entry::fromArray('ou=empty-area,dc=foo,dc=bar')
                ->reset(AttributeTypeOid::NAME_ADMINISTRATIVE_ROLE),
        );

        $entries = $this->ldapClient()->search(
            Operations::search(
                Filters::present('objectClass'),
                AttributeTypeOid::NAME_ADMINISTRATIVE_ROLE,
            )
                ->base('ou=empty-area,dc=foo,dc=bar')
                ->useBaseScope(),
        );

        self::assertNull($entries->first()?->get(AttributeTypeOid::NAME_ADMINISTRATIVE_ROLE));
    }

    /**
     * The shared server holds the port, so it stands down and is relaunched in tearDown.
     */
    private function startLenientRelaxServer(): void
    {
        $this->stopServer();
        $this->createServerProcess(
            'tcp',
            [
                '--validation-mode=lenient',
                '--allow-relax',
            ],
        );
    }

    private function makeParent(
        string $ou,
        bool $isAdministrative,
    ): void {
        $attributes = [
            'ou' => $ou,
            'objectClass' => 'organizationalUnit',
        ];

        if ($isAdministrative) {
            $attributes[AttributeTypeOid::NAME_ADMINISTRATIVE_ROLE] = self::ADMIN_ROLE;
        }

        $this->ldapClient()->create(Entry::fromArray(
            'ou=' . $ou . ',dc=foo,dc=bar',
            $attributes,
        ));
    }

    private function subentry(
        string $dn,
        string $specification,
    ): Entry {
        return Entry::fromArray(
            $dn,
            [
                'cn' => explode('=', explode(',', $dn, 2)[0], 2)[1],
                'objectClass' => ObjectClassOid::NAME_SUBENTRY,
                AttributeTypeOid::NAME_SUBTREE_SPECIFICATION => $specification,
            ],
        );
    }

    private function readSpecification(string $dn): ?string
    {
        $entries = $this->ldapClient()->search(
            Operations::search(
                Filters::present('objectClass'),
                AttributeTypeOid::NAME_SUBTREE_SPECIFICATION,
            )
                ->base($dn)
                ->useBaseScope(),
        );

        return $entries->first()?->get(AttributeTypeOid::NAME_SUBTREE_SPECIFICATION)?->firstValue();
    }
}
