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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Schema\AttributeTypeSpelling;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Search\Filter\GreaterThanOrEqualFilter;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\TestCase;

final class AttributeTypeSpellingTest extends TestCase
{
    private AttributeTypeSpelling $subject;

    protected function setUp(): void
    {
        $this->subject = new AttributeTypeSpelling(
            SchemaResource::Core->load()->merge(SchemaResource::PasswordPolicy->load()),
        );
    }

    public function test_a_dn_respells_the_type_of_every_rdn(): void
    {
        $result = $this->subject->dn(new Dn('2.5.4.3=Alice,organizationalUnitName=People,dc=example,dc=com'));

        self::assertSame(
            'cn=Alice,ou=People,dc=example,dc=com',
            $result->toString(),
        );
    }

    public function test_a_dn_naming_only_primary_names_is_returned_as_is(): void
    {
        $dn = new Dn('CN=Alice,dc=example,dc=com');

        self::assertSame(
            $dn,
            $this->subject->dn($dn),
        );
    }

    public function test_a_dn_that_does_not_parse_is_returned_as_is(): void
    {
        $dn = new Dn('alice@example.com');

        self::assertSame(
            $dn,
            $this->subject->dn($dn),
        );
    }

    public function test_an_rdn_value_keeps_its_escaped_form(): void
    {
        $result = $this->subject->dn(new Dn('commonName=Smith\2C John,dc=example,dc=com'));

        self::assertSame(
            'cn=Smith\2C John,dc=example,dc=com',
            $result->toString(),
        );
    }

    public function test_a_multivalued_rdn_respells_each_component(): void
    {
        $result = $this->subject->rdn(Rdn::create('commonName=Alice+surname=Smith'));

        self::assertSame(
            'cn=Alice+sn=Smith',
            $result->toString(),
        );
    }

    public function test_an_entry_attribute_keeps_its_options_and_values(): void
    {
        $result = $this->subject->entry(new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('surname;lang-en', 'Smith', 'Smythe'),
        ));

        self::assertSame(
            'sn;lang-en',
            $result->getAttributes()[0]->getDescription(),
        );
        self::assertSame(
            ['Smith', 'Smythe'],
            $result->getAttributes()[0]->getValues(),
        );
    }

    public function test_an_entry_naming_only_primary_names_is_returned_as_is(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('sn', 'Smith'),
        );

        self::assertSame(
            $entry,
            $this->subject->entry($entry),
        );
    }

    public function test_a_change_keeps_its_type(): void
    {
        $result = $this->subject->change(Change::delete(new Attribute('surname', 'Smith')));

        self::assertSame(
            Change::TYPE_DELETE,
            $result->getType(),
        );
        self::assertSame(
            'sn',
            $result->getAttribute()->getDescription(),
        );
    }

    public function test_a_description_keeps_its_options(): void
    {
        self::assertSame(
            'sn;lang-en',
            $this->subject->description('surname;lang-en'),
        );
    }

    public function test_a_description_naming_no_schema_type_is_kept_as_given(): void
    {
        self::assertSame(
            '*',
            $this->subject->description('*'),
        );
    }

    public function test_rewrite_filter_respells_every_nested_item_in_place(): void
    {
        $filter = Filters::and(
            Filters::equal('surname', 'Smith'),
            Filters::not(Filters::present('commonName')),
            new GreaterThanOrEqualFilter('2.5.4.4', 'A'),
        );

        $this->subject->rewriteFilter($filter);

        self::assertSame(
            '(&(sn=Smith)(!(cn=*))(sn>=A))',
            $filter->toString(),
        );
    }

    public function test_an_object_class_value_spelled_by_oid_is_respelled_by_its_primary_name(): void
    {
        $result = $this->subject->entry(new Entry(
            new Dn('cn=policy,dc=example,dc=com'),
            new Attribute('objectClass', 'top', '2.5.17.0', '2.5.6.1'),
        ));

        self::assertSame(
            ['top', 'subentry', 'alias'],
            $result->getAttributes()[0]->getValues(),
        );
    }

    public function test_an_object_class_value_differing_only_by_case_is_kept_as_given(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'PERSON'),
        );

        self::assertSame(
            $entry,
            $this->subject->entry($entry),
        );
    }

    public function test_an_object_identifier_value_naming_an_attribute_type_is_respelled(): void
    {
        $result = $this->subject->entry(new Entry(
            new Dn('cn=policy,dc=example,dc=com'),
            new Attribute('pwdAttribute', '2.5.4.35'),
        ));

        self::assertSame(
            ['userPassword'],
            $result->getAttributes()[0]->getValues(),
        );
    }

    public function test_an_unknown_object_identifier_value_is_kept_as_given(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', '1.2.3.4.5'),
        );

        self::assertSame(
            $entry,
            $this->subject->entry($entry),
        );
    }

    public function test_a_dn_value_respells_the_types_it_names(): void
    {
        $result = $this->subject->entry(new Entry(
            new Dn('cn=staff,dc=example,dc=com'),
            new Attribute('member', '2.5.4.3=Alice,dc=example,dc=com', 'commonName=Bob,dc=example,dc=com'),
        ));

        self::assertSame(
            ['cn=Alice,dc=example,dc=com', 'cn=Bob,dc=example,dc=com'],
            $result->getAttributes()[0]->getValues(),
        );
    }

    public function test_a_dn_value_of_a_subtype_is_respelled(): void
    {
        $result = $this->subject->entry(new Entry(
            new Dn('cn=staff,dc=example,dc=com'),
            new Attribute('roleOccupant', 'commonName=Alice,dc=example,dc=com'),
        ));

        self::assertSame(
            ['cn=Alice,dc=example,dc=com'],
            $result->getAttributes()[0]->getValues(),
        );
    }

    public function test_a_dn_value_that_does_not_parse_is_kept_as_given(): void
    {
        $entry = new Entry(
            new Dn('cn=staff,dc=example,dc=com'),
            new Attribute('seeAlso', 'not a dn'),
        );

        self::assertSame(
            $entry,
            $this->subject->entry($entry),
        );
    }

    public function test_a_name_and_optional_uid_value_respells_only_its_name(): void
    {
        $result = $this->subject->entry(new Entry(
            new Dn('cn=staff,dc=example,dc=com'),
            new Attribute(
                'uniqueMember',
                "2.5.4.3=Alice,dc=example,dc=com#'0101'B",
                'commonName=Bob,dc=example,dc=com',
            ),
        ));

        self::assertSame(
            ["cn=Alice,dc=example,dc=com#'0101'B", 'cn=Bob,dc=example,dc=com'],
            $result->getAttributes()[0]->getValues(),
        );
    }

    public function test_a_change_respells_the_dn_values_it_carries(): void
    {
        $result = $this->subject->change(Change::add(new Attribute('member', '2.5.4.3=Alice,dc=example,dc=com')));

        self::assertSame(
            ['cn=Alice,dc=example,dc=com'],
            $result->getAttribute()->getValues(),
        );
    }

    public function test_a_value_of_a_syntax_naming_no_type_is_kept_as_given(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('description', '2.5.4.3=Alice'),
        );

        self::assertSame(
            $entry,
            $this->subject->entry($entry),
        );
    }

    public function test_rewrite_filter_respells_assertion_values_naming_types(): void
    {
        $filter = Filters::and(
            Filters::equal('objectClass', '2.5.17.0'),
            Filters::equal('2.5.4.31', 'commonName=Alice,dc=example,dc=com'),
            Filters::equal('description', '2.5.4.3=Alice'),
        );

        $this->subject->rewriteFilter($filter);

        self::assertSame(
            '(&(objectClass=subentry)(member=cn=Alice,dc=example,dc=com)(description=2.5.4.3=Alice))',
            $filter->toString(),
        );
    }

    public function test_rewrite_filter_respells_an_extensible_match_value_by_its_rule_assertion_syntax(): void
    {
        $filter = Filters::and(
            Filters::extensible('seeAlso', 'commonName=Alice,dc=example,dc=com', 'distinguishedNameMatch'),
            Filters::extensible(null, '2.5.4.3=Bob,dc=example,dc=com', '2.5.13.1'),
            Filters::extensible('member', 'commonName=Carol,dc=example,dc=com', null),
        );

        $this->subject->rewriteFilter($filter);

        self::assertSame(
            '(&(seeAlso:distinguishedNameMatch:=cn=Alice,dc=example,dc=com)'
            . '(:2.5.13.1:=cn=Bob,dc=example,dc=com)'
            . '(member:=cn=Carol,dc=example,dc=com))',
            $filter->toString(),
        );
    }

    public function test_a_change_naming_the_primary_name_is_returned_as_is(): void
    {
        $change = Change::replace(new Attribute('sn', 'Smith'));

        self::assertSame(
            $change,
            $this->subject->change($change),
        );
    }
}
