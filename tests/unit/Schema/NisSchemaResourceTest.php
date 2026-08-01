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

use FreeDSx\Ldap\Schema\Definition\MatchingRuleOid;
use FreeDSx\Ldap\Schema\Definition\Nis\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Definition\Nis\ObjectClassOid;
use FreeDSx\Ldap\Schema\Definition\ObjectClassType;
use FreeDSx\Ldap\Schema\Definition\SyntaxOid;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Schema\Schema;
use PHPUnit\Framework\TestCase;

/**
 * Verifies the definitions shipped in resources/ldap-schema/nis.ldif.
 */
final class NisSchemaResourceTest extends TestCase
{
    private Schema $schema;

    protected function setUp(): void
    {
        $this->schema = SchemaResource::Nis->load();
    }

    public function test_registers_all_13_attribute_types(): void
    {
        self::assertCount(
            13,
            $this->schema->getAttributeTypes(),
        );
    }

    public function test_uid_number_uses_integer_syntax_and_equality_with_no_ordering(): void
    {
        $uidNumber = $this->schema->getAttributeType(AttributeTypeOid::NAME_UID_NUMBER);

        self::assertNotNull($uidNumber);
        self::assertSame(
            SyntaxOid::OID_INTEGER,
            $uidNumber->syntaxOid,
        );
        self::assertSame(
            MatchingRuleOid::OID_INTEGER_MATCH,
            $uidNumber->equalityOid,
        );
        self::assertNull($uidNumber->orderingOid);
        self::assertTrue($uidNumber->singleValue);
    }

    public function test_posix_account_requires_the_core_posix_attributes(): void
    {
        $posixAccount = $this->schema->getObjectClass(ObjectClassOid::NAME_POSIX_ACCOUNT);

        self::assertNotNull($posixAccount);
        self::assertSame(
            ObjectClassType::AuxiliaryClass,
            $posixAccount->type,
        );
        self::assertContains(
            AttributeTypeOid::NAME_UID_NUMBER,
            $posixAccount->must,
        );
        self::assertContains(
            AttributeTypeOid::NAME_GID_NUMBER,
            $posixAccount->must,
        );
    }

    public function test_integer_attributes_resolve_as_integer_ordered_via_syntax(): void
    {
        self::assertTrue($this->schema->isIntegerOrdered(AttributeTypeOid::NAME_UID_NUMBER));
        self::assertTrue($this->schema->isIntegerOrdered(AttributeTypeOid::NAME_SHADOW_MAX));
    }

    public function test_string_attributes_do_not_resolve_as_integer_ordered(): void
    {
        self::assertFalse($this->schema->isIntegerOrdered(AttributeTypeOid::NAME_HOME_DIRECTORY));
    }
}
