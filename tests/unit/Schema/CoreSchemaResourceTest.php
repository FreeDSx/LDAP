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

use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Definition\AttributeUsage;
use FreeDSx\Ldap\Schema\Definition\MatchingRuleOid;
use FreeDSx\Ldap\Schema\Definition\ObjectClassOid;
use FreeDSx\Ldap\Schema\Definition\ObjectClassType;
use FreeDSx\Ldap\Schema\Definition\SyntaxOid;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaResource;
use PHPUnit\Framework\TestCase;

/**
 * Verifies the definitions shipped in resources/ldap-schema/core.ldif.
 */
final class CoreSchemaResourceTest extends TestCase
{
    private Schema $schema;

    protected function setUp(): void
    {
        $this->schema = SchemaResource::Core->load();
    }

    public function test_it_loads_a_non_empty_schema(): void
    {
        self::assertNotEmpty($this->schema->getAttributeTypes());
        self::assertNotEmpty($this->schema->getObjectClasses());
    }

    /**
     * A rule an attribute names but the schema cannot resolve silently falls back to case-insensitive matching.
     */
    public function test_every_matching_rule_an_attribute_names_resolves_to_a_comparator(): void
    {
        $unresolved = [];

        foreach ($this->schema->getAttributeTypes() as $attributeType) {
            $rules = [
                $attributeType->equalityOid,
                $attributeType->orderingOid,
                $attributeType->substringOid,
            ];

            foreach (array_filter($rules) as $ruleOid) {
                if ($this->schema->getComparator($ruleOid) === null) {
                    $unresolved[$ruleOid] = true;
                }
            }
        }

        self::assertSame(
            [],
            array_keys($unresolved),
        );
    }

    public function test_has_expected_syntax_count(): void
    {
        self::assertCount(
            25,
            $this->schema->getLdapSyntaxes(),
        );
    }

    public function test_has_expected_matching_rule_count(): void
    {
        self::assertCount(
            32,
            $this->schema->getMatchingRules(),
        );
    }

    public function test_has_expected_attribute_type_count(): void
    {
        self::assertCount(
            48,
            $this->schema->getAttributeTypes(),
        );
    }

    public function test_has_expected_object_class_count(): void
    {
        self::assertCount(
            14,
            $this->schema->getObjectClasses(),
        );
    }

    // --- syntaxes ---

    public function test_directory_string_syntax_registered(): void
    {
        $syntax = $this->schema->getSyntax(SyntaxOid::OID_DIRECTORY_STRING);

        self::assertNotNull($syntax);
        self::assertSame(
            SyntaxOid::DESC_DIRECTORY_STRING,
            $syntax->desc,
        );
    }

    public function test_integer_syntax_registered(): void
    {
        self::assertNotNull($this->schema->getSyntax(SyntaxOid::OID_INTEGER));
    }

    public function test_uuid_syntax_registered(): void
    {
        $syntax = $this->schema->getSyntax(SyntaxOid::OID_UUID);

        self::assertNotNull($syntax);
        self::assertSame(
            SyntaxOid::DESC_UUID,
            $syntax->desc,
        );
    }

    public function test_entry_uuid_uses_the_uuid_syntax(): void
    {
        self::assertSame(
            SyntaxOid::OID_UUID,
            $this->schema->getAttributeType(AttributeTypeOid::NAME_ENTRY_UUID)?->syntaxOid,
        );
    }

    // --- matching rules ---

    public function test_case_ignore_match_registered_by_oid(): void
    {
        self::assertNotNull(
            $this->schema->getMatchingRule(MatchingRuleOid::OID_CASE_IGNORE_MATCH),
        );
    }

    public function test_case_ignore_match_registered_by_name(): void
    {
        self::assertNotNull(
            $this->schema->getMatchingRule(MatchingRuleOid::NAME_CASE_IGNORE_MATCH),
        );
    }

    public function test_case_exact_match_registered(): void
    {
        self::assertNotNull(
            $this->schema->getMatchingRule(MatchingRuleOid::OID_CASE_EXACT_MATCH),
        );
    }

    public function test_distinguished_name_match_registered(): void
    {
        self::assertNotNull(
            $this->schema->getMatchingRule(MatchingRuleOid::OID_DISTINGUISHED_NAME_MATCH),
        );
    }

    public function test_integer_match_registered(): void
    {
        self::assertNotNull(
            $this->schema->getMatchingRule(MatchingRuleOid::OID_INTEGER_MATCH),
        );
    }

    public function test_boolean_match_registered(): void
    {
        self::assertNotNull(
            $this->schema->getMatchingRule(MatchingRuleOid::OID_BOOLEAN_MATCH),
        );
    }

    public function test_bit_and_match_registered(): void
    {
        self::assertNotNull(
            $this->schema->getMatchingRule(MatchingRuleOid::OID_BIT_AND_MATCH),
        );
    }

    public function test_bit_or_match_registered(): void
    {
        self::assertNotNull(
            $this->schema->getMatchingRule(MatchingRuleOid::OID_BIT_OR_MATCH),
        );
    }

    // --- attribute types ---

    public function test_cn_registered_by_oid(): void
    {
        self::assertNotNull(
            $this->schema->getAttributeType(AttributeTypeOid::OID_CN),
        );
    }

    public function test_cn_registered_by_name(): void
    {
        self::assertNotNull(
            $this->schema->getAttributeType(AttributeTypeOid::NAME_CN),
        );
    }

    public function test_cn_registered_by_alias(): void
    {
        self::assertNotNull(
            $this->schema->getAttributeType(AttributeTypeOid::ALIAS_CN),
        );
    }

    public function test_uid_registered(): void
    {
        self::assertNotNull(
            $this->schema->getAttributeType(AttributeTypeOid::OID_UID),
        );
    }

    public function test_create_timestamp_is_no_user_modification(): void
    {
        $attr = $this->schema->getAttributeType(AttributeTypeOid::NAME_CREATE_TIMESTAMP);

        self::assertNotNull($attr);
        self::assertTrue($attr->noUserModification);
    }

    public function test_object_class_attribute_registered(): void
    {
        self::assertNotNull(
            $this->schema->getAttributeType(AttributeTypeOid::NAME_OBJECT_CLASS),
        );
    }

    // --- object classes ---

    public function test_top_registered(): void
    {
        self::assertNotNull(
            $this->schema->getObjectClass(ObjectClassOid::NAME_TOP),
        );
    }

    public function test_alias_registered(): void
    {
        $alias = $this->schema->getObjectClass(ObjectClassOid::NAME_ALIAS);

        self::assertNotNull($alias);
        self::assertContains(
            AttributeTypeOid::NAME_ALIASED_OBJECT_NAME,
            $alias->must,
        );
    }

    public function test_person_registered_by_oid(): void
    {
        self::assertNotNull(
            $this->schema->getObjectClass(ObjectClassOid::OID_PERSON),
        );
    }

    public function test_person_registered_by_name(): void
    {
        self::assertNotNull(
            $this->schema->getObjectClass(ObjectClassOid::NAME_PERSON),
        );
    }

    public function test_inet_org_person_registered(): void
    {
        self::assertNotNull(
            $this->schema->getObjectClass(ObjectClassOid::NAME_INET_ORG_PERSON),
        );
    }

    public function test_extensible_object_registered(): void
    {
        self::assertNotNull(
            $this->schema->getObjectClass(ObjectClassOid::NAME_EXTENSIBLE_OBJECT),
        );
    }

    public function test_subschema_registered(): void
    {
        self::assertNotNull(
            $this->schema->getObjectClass(ObjectClassOid::NAME_SUBSCHEMA),
        );
    }

    public function test_subtree_specification_syntax_registered(): void
    {
        $syntax = $this->schema->getSyntax(SyntaxOid::OID_SUBTREE_SPECIFICATION);

        self::assertNotNull($syntax);
        self::assertSame(
            SyntaxOid::DESC_SUBTREE_SPECIFICATION,
            $syntax->desc,
        );
    }

    public function test_subtree_specification_is_single_valued_and_operational(): void
    {
        $attr = $this->schema->getAttributeType(AttributeTypeOid::NAME_SUBTREE_SPECIFICATION);

        self::assertNotNull($attr);
        self::assertTrue($attr->singleValue);
        self::assertSame(
            AttributeUsage::DirectoryOperation,
            $attr->usage,
        );
        self::assertSame(
            SyntaxOid::OID_SUBTREE_SPECIFICATION,
            $attr->syntaxOid,
        );
    }

    /**
     * It is user-writable by design, so placement and syntax checks are the only guard on it.
     */
    public function test_subtree_specification_is_user_modifiable(): void
    {
        $attr = $this->schema->getAttributeType(AttributeTypeOid::NAME_SUBTREE_SPECIFICATION);

        self::assertNotNull($attr);
        self::assertFalse($attr->noUserModification);
    }

    public function test_administrative_role_is_multi_valued_and_operational(): void
    {
        $attr = $this->schema->getAttributeType(AttributeTypeOid::NAME_ADMINISTRATIVE_ROLE);

        self::assertNotNull($attr);
        self::assertFalse($attr->singleValue);
        self::assertSame(
            AttributeUsage::DirectoryOperation,
            $attr->usage,
        );
    }

    public function test_subentry_is_structural_and_requires_a_subtree_specification(): void
    {
        $subentry = $this->schema->getObjectClass(ObjectClassOid::NAME_SUBENTRY);

        self::assertNotNull($subentry);
        self::assertSame(
            ObjectClassType::StructuralClass,
            $subentry->type,
        );
        self::assertContains(
            AttributeTypeOid::NAME_SUBTREE_SPECIFICATION,
            $subentry->must,
        );
        self::assertContains(
            AttributeTypeOid::NAME_CN,
            $subentry->must,
        );
    }

    public function test_subentry_registered_by_oid(): void
    {
        self::assertNotNull(
            $this->schema->getObjectClass(ObjectClassOid::OID_SUBENTRY),
        );
    }
}
