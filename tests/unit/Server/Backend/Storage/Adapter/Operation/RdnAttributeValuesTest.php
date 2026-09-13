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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\Operation;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Schema\Matching\EqualityComparatorResolver;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Operation\RdnAttributeValues;
use PHPUnit\Framework\TestCase;

final class RdnAttributeValuesTest extends TestCase
{
    private RdnAttributeValues $subject;

    protected function setUp(): void
    {
        $this->subject = new RdnAttributeValues(new EqualityComparatorResolver(SchemaResource::Core->load()));
    }

    public function test_merge_adds_a_missing_naming_attribute(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('sn', 'Smith'),
        );

        $this->subject->merge($entry);

        self::assertSame(
            ['Alice'],
            $entry->get('cn')?->getValues(),
        );
    }

    public function test_merge_keeps_an_existing_value_alongside_the_naming_one(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Other'),
        );

        $this->subject->merge($entry);

        self::assertSame(
            ['Other', 'Alice'],
            $entry->get('cn')?->getValues(),
        );
    }

    public function test_merge_does_not_duplicate_a_value_differing_only_by_case(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'alice'),
        );

        $this->subject->merge($entry);

        self::assertSame(
            ['alice'],
            $entry->get('cn')?->getValues(),
        );
    }

    public function test_merge_does_not_duplicate_a_value_differing_only_by_non_ascii_case(): void
    {
        $entry = new Entry(
            new Dn('cn=Über,dc=example,dc=com'),
            new Attribute('cn', 'über'),
        );

        $this->subject->merge($entry);

        self::assertSame(
            ['über'],
            $entry->get('cn')?->getValues(),
        );
    }

    public function test_merge_does_not_duplicate_a_value_differing_only_by_insignificant_spaces(): void
    {
        $entry = new Entry(
            new Dn('cn=F  One,dc=example,dc=com'),
            new Attribute('cn', 'F One'),
        );

        $this->subject->merge($entry);

        self::assertSame(
            ['F One'],
            $entry->get('cn')?->getValues(),
        );
    }

    public function test_merge_adds_a_case_variant_of_a_case_exact_value(): void
    {
        $entry = new Entry(
            new Dn('labeledURI=Xyz,dc=example,dc=com'),
            new Attribute('labeledURI', 'xyz'),
        );

        $this->subject->merge($entry);

        self::assertSame(
            ['xyz', 'Xyz'],
            $entry->get('labeledURI')?->getValues(),
        );
    }

    public function test_merge_unescapes_the_naming_value(): void
    {
        $entry = new Entry(
            new Dn('cn=Smith\2C John,dc=example,dc=com'),
            new Attribute('sn', 'Smith'),
        );

        $this->subject->merge($entry);

        self::assertSame(
            ['Smith, John'],
            $entry->get('cn')?->getValues(),
        );
    }

    public function test_merge_covers_every_component_of_a_multivalued_rdn(): void
    {
        $entry = new Entry(new Dn('cn=Alice+sn=Smith,dc=example,dc=com'));

        $this->subject->merge($entry);

        self::assertSame(
            ['Alice'],
            $entry->get('cn')?->getValues(),
        );
        self::assertSame(
            ['Smith'],
            $entry->get('sn')?->getValues(),
        );
    }

    public function test_merge_is_a_no_op_for_the_root_dse(): void
    {
        $entry = new Entry(new Dn(''));

        $this->subject->merge($entry);

        self::assertCount(
            0,
            $entry->getAttributes(),
        );
    }

    public function test_remove_drops_a_value_differing_only_by_non_ascii_case(): void
    {
        $entry = new Entry(
            new Dn('cn=École,dc=example,dc=com'),
            new Attribute('cn', 'école', 'other'),
        );

        $this->subject->remove(
            $entry,
            Rdn::create('cn=École'),
        );

        self::assertSame(
            ['other'],
            $entry->get('cn')?->getValues(),
        );
    }

    public function test_remove_keeps_case_variants_of_a_case_exact_value(): void
    {
        $entry = new Entry(
            new Dn('labeledURI=Xyz,dc=example,dc=com'),
            new Attribute('labeledURI', 'Xyz', 'xyz', 'XYZ'),
        );

        $this->subject->remove(
            $entry,
            Rdn::create('labeledURI=Xyz'),
        );

        self::assertSame(
            ['xyz', 'XYZ'],
            $entry->get('labeledURI')?->getValues(),
        );
    }

    public function test_remove_unescapes_the_naming_value(): void
    {
        $entry = new Entry(
            new Dn('cn=Smith\2C John,dc=example,dc=com'),
            new Attribute('cn', 'Smith, John', 'John'),
        );

        $this->subject->remove(
            $entry,
            Rdn::create('cn=Smith\2C John'),
        );

        self::assertSame(
            ['John'],
            $entry->get('cn')?->getValues(),
        );
    }

    public function test_remove_drops_an_attribute_left_with_no_values(): void
    {
        $entry = new Entry(
            new Dn('uid=asmith,dc=example,dc=com'),
            new Attribute('uid', 'ASmith'),
            new Attribute('cn', 'Alice'),
        );

        $this->subject->remove(
            $entry,
            Rdn::create('uid=asmith'),
        );

        self::assertFalse($entry->has('uid'));
    }

    public function test_remove_ignores_a_component_the_entry_does_not_hold(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Alice'),
        );

        $this->subject->remove(
            $entry,
            Rdn::create('uid=asmith'),
        );

        self::assertSame(
            ['Alice'],
            $entry->get('cn')?->getValues(),
        );
    }
}
