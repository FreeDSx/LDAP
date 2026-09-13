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
        $this->subject = new AttributeTypeSpelling(SchemaResource::Core->load());
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

    public function test_a_change_naming_the_primary_name_is_returned_as_is(): void
    {
        $change = Change::replace(new Attribute('sn', 'Smith'));

        self::assertSame(
            $change,
            $this->subject->change($change),
        );
    }
}
