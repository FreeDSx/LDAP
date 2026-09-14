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

namespace Tests\Unit\FreeDSx\Ldap\Server\AccessControl;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\PrivilegedBypassAccessControl;
use FreeDSx\Ldap\Server\AccessControl\RuleBasedAccessControl;
use FreeDSx\Ldap\Server\AccessControl\WithheldAttributePolicy;
use FreeDSx\Ldap\Server\AccessControl\WithheldValueModifyGuard;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\ManagerToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\TestCase;

final class WithheldValueModifyGuardTest extends TestCase
{
    private const TARGET = 'cn=user,dc=foo,dc=bar';

    private WithheldValueModifyGuard $subject;

    private TokenInterface $other;

    protected function setUp(): void
    {
        // Core marks userPassword X-CONFIDENTIAL, so it is withheld; cn is not.
        $this->subject = new WithheldValueModifyGuard(new WithheldAttributePolicy(
            new RuleBasedAccessControl(AclRules::fromEmpty()),
            SchemaResource::Core->load(),
        ));
        $this->other = BindToken::fromDn('cn=admin,dc=foo,dc=bar');
    }

    public function test_it_refuses_a_value_add_of_a_withheld_attribute_on_another_entry(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->subject->assertAllowed(
            Operations::modify(self::TARGET, Change::add('userPassword', '{SHA}guess')),
            $this->other,
        );
    }

    public function test_it_refuses_a_whole_attribute_delete_of_a_withheld_attribute_on_another_entry(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->subject->assertAllowed(
            Operations::modify(self::TARGET, Change::delete('userPassword')),
            $this->other,
        );
    }

    public function test_it_allows_a_replace_of_a_withheld_attribute_on_another_entry(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->assertAllowed(
            Operations::modify(self::TARGET, Change::replace('userPassword', '{SHA}new')),
            $this->other,
        );
    }

    public function test_it_allows_a_value_modify_of_a_readable_attribute_on_another_entry(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->assertAllowed(
            Operations::modify(self::TARGET, Change::add('description', 'note')),
            $this->other,
        );
    }

    public function test_it_allows_a_value_modify_of_a_withheld_attribute_on_the_identitys_own_entry(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->assertAllowed(
            Operations::modify(self::TARGET, Change::delete('userPassword', '{SHA}old')),
            BindToken::fromDn(self::TARGET),
        );
    }

    public function test_a_privileged_manager_is_not_restricted(): void
    {
        $this->expectNotToPerformAssertions();

        $guard = new WithheldValueModifyGuard(new WithheldAttributePolicy(
            new PrivilegedBypassAccessControl(new RuleBasedAccessControl(AclRules::fromEmpty())),
            SchemaResource::Core->load(),
        ));

        $guard->assertAllowed(
            Operations::modify(self::TARGET, Change::add('userPassword', '{SHA}guess')),
            new ManagerToken(new Dn('cn=manager')),
        );
    }
}
