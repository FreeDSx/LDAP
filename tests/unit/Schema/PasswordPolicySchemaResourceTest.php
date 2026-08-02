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

namespace Tests\Unit\FreeDSx\Ldap\Schema;

use FreeDSx\Ldap\Schema\Definition\AttributeUsage;
use FreeDSx\Ldap\Schema\Definition\ObjectClassType;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Schema\Definition\SyntaxOid;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Schema\Schema;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Verifies the definitions shipped in resources/ldap-schema/ppolicy.ldif.
 */
final class PasswordPolicySchemaResourceTest extends TestCase
{
    private Schema $schema;

    protected function setUp(): void
    {
        $this->schema = SchemaResource::PasswordPolicy->load();
    }

    public function test_registers_all_30_attribute_types(): void
    {
        self::assertCount(
            30,
            $this->schema->getAttributeTypes(),
        );
    }

    public function test_registers_pwd_policy_object_class(): void
    {
        $oc = $this->schema->getObjectClass(PasswordPolicyOid::NAME_PWD_POLICY);

        self::assertNotNull($oc);
        self::assertSame(
            ObjectClassType::AuxiliaryClass,
            $oc->type,
        );
        self::assertContains(
            PasswordPolicyOid::NAME_PWD_ATTRIBUTE,
            $oc->must,
        );
        self::assertCount(
            19,
            $oc->may,
        );
    }

    #[DataProvider('userStateAttributeProvider')]
    public function test_user_state_attributes_are_operational_and_no_user_modification(string $name): void
    {
        $type = $this->schema->getAttributeType($name);

        self::assertNotNull($type);
        self::assertTrue($type->noUserModification);
        self::assertSame(
            AttributeUsage::DirectoryOperation,
            $type->usage,
        );
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function userStateAttributeProvider(): array
    {
        return [
            'pwdChangedTime' => [PasswordPolicyOid::NAME_PWD_CHANGED_TIME],
            'pwdAccountLockedTime' => [PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME],
            'pwdFailureTime' => [PasswordPolicyOid::NAME_PWD_FAILURE_TIME],
            'pwdHistory' => [PasswordPolicyOid::NAME_PWD_HISTORY],
            'pwdGraceUseTime' => [PasswordPolicyOid::NAME_PWD_GRACE_USE_TIME],
            'pwdPolicySubentry' => [PasswordPolicyOid::NAME_PWD_POLICY_SUBENTRY],
            'pwdStartTime' => [PasswordPolicyOid::NAME_PWD_START_TIME],
            'pwdEndTime' => [PasswordPolicyOid::NAME_PWD_END_TIME],
            'pwdLastSuccess' => [PasswordPolicyOid::NAME_PWD_LAST_SUCCESS],
        ];
    }

    #[DataProvider('policyConfigAttributeProvider')]
    public function test_policy_config_attributes_are_user_application(string $name): void
    {
        $type = $this->schema->getAttributeType($name);

        self::assertNotNull($type);
        self::assertFalse($type->noUserModification);
        self::assertSame(
            AttributeUsage::UserApplications,
            $type->usage,
        );
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function policyConfigAttributeProvider(): array
    {
        return [
            'pwdAttribute' => [PasswordPolicyOid::NAME_PWD_ATTRIBUTE],
            'pwdMinAge' => [PasswordPolicyOid::NAME_PWD_MIN_AGE],
            'pwdMaxAge' => [PasswordPolicyOid::NAME_PWD_MAX_AGE],
            'pwdInHistory' => [PasswordPolicyOid::NAME_PWD_IN_HISTORY],
            'pwdCheckQuality' => [PasswordPolicyOid::NAME_PWD_CHECK_QUALITY],
            'pwdMinLength' => [PasswordPolicyOid::NAME_PWD_MIN_LENGTH],
            'pwdMaxLength' => [PasswordPolicyOid::NAME_PWD_MAX_LENGTH],
            'pwdExpireWarning' => [PasswordPolicyOid::NAME_PWD_EXPIRE_WARNING],
            'pwdGraceAuthNLimit' => [PasswordPolicyOid::NAME_PWD_GRACE_AUTHN_LIMIT],
            'pwdGraceExpiry' => [PasswordPolicyOid::NAME_PWD_GRACE_EXPIRY],
            'pwdLockout' => [PasswordPolicyOid::NAME_PWD_LOCKOUT],
            'pwdLockoutDuration' => [PasswordPolicyOid::NAME_PWD_LOCKOUT_DURATION],
            'pwdMaxFailure' => [PasswordPolicyOid::NAME_PWD_MAX_FAILURE],
            'pwdFailureCountInterval' => [PasswordPolicyOid::NAME_PWD_FAILURE_COUNT_INTERVAL],
            'pwdMustChange' => [PasswordPolicyOid::NAME_PWD_MUST_CHANGE],
            'pwdAllowUserChange' => [PasswordPolicyOid::NAME_PWD_ALLOW_USER_CHANGE],
            'pwdSafeModify' => [PasswordPolicyOid::NAME_PWD_SAFE_MODIFY],
            'pwdMinDelay' => [PasswordPolicyOid::NAME_PWD_MIN_DELAY],
            'pwdMaxDelay' => [PasswordPolicyOid::NAME_PWD_MAX_DELAY],
            'pwdMaxIdle' => [PasswordPolicyOid::NAME_PWD_MAX_IDLE],
        ];
    }

    public function test_pwd_history_uses_octet_string_syntax(): void
    {
        $type = $this->schema->getAttributeType(PasswordPolicyOid::NAME_PWD_HISTORY);

        self::assertNotNull($type);
        self::assertSame(
            SyntaxOid::OID_OCTET_STRING,
            $type->syntaxOid,
        );
        self::assertFalse($type->singleValue);
    }

    public function test_pwd_failure_time_is_multi_valued(): void
    {
        $type = $this->schema->getAttributeType(PasswordPolicyOid::NAME_PWD_FAILURE_TIME);

        self::assertNotNull($type);
        self::assertFalse($type->singleValue);
    }

    public function test_pwd_changed_time_is_single_valued(): void
    {
        $type = $this->schema->getAttributeType(PasswordPolicyOid::NAME_PWD_CHANGED_TIME);

        self::assertNotNull($type);
        self::assertTrue($type->singleValue);
    }

    public function test_pwd_grace_use_time_has_no_ordering_rule(): void
    {
        $type = $this->schema->getAttributeType(PasswordPolicyOid::NAME_PWD_GRACE_USE_TIME);

        self::assertNotNull($type);
        self::assertNull($type->orderingOid);
    }

    public function test_pwd_change_time_has_ordering_rule(): void
    {
        $type = $this->schema->getAttributeType(PasswordPolicyOid::NAME_PWD_CHANGED_TIME);

        self::assertNotNull($type);
        self::assertNotNull($type->orderingOid);
    }
}
