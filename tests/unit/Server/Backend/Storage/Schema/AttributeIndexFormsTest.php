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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Schema;

use FreeDSx\Ldap\Schema\Definition\AttributeType;
use FreeDSx\Ldap\Schema\Definition\MatchingRuleOid;
use FreeDSx\Ldap\Schema\Matching\EqualityComparatorResolver;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeIndexForms;
use PHPUnit\Framework\TestCase;

final class AttributeIndexFormsTest extends TestCase
{
    private AttributeIndexForms $subject;

    protected function setUp(): void
    {
        $schema = SchemaResource::Core->load();
        $schema->addAttributeType(new AttributeType(
            oid: '1.3.6.1.4.1.99999.1.1',
            names: ['dnSubstrings'],
            substringOid: MatchingRuleOid::OID_DISTINGUISHED_NAME_MATCH,
        ));
        $this->subject = new AttributeIndexForms(
            $schema,
            new EqualityComparatorResolver($schema),
        );
    }

    public function test_a_substring_key_is_the_value_as_the_substr_rule_prepares_it(): void
    {
        self::assertSame(
            'strasse und gasse',
            $this->subject->substringKey(
                'sn',
                "  Straße\u{00A0}und   Gasse ",
            ),
        );
    }

    public function test_a_substring_fragment_keeps_its_edge_spaces(): void
    {
        self::assertSame(
            ' strasse ',
            $this->subject->substringFragment(
                'sn',
                ' Straße ',
            ),
        );
    }

    public function test_a_substring_key_follows_the_attributes_own_substr_rule(): void
    {
        self::assertSame(
            '+15550100',
            $this->subject->substringKey(
                'telephoneNumber',
                '+1 555-0100',
            ),
        );
        self::assertSame(
            '55501',
            $this->subject->substringFragment(
                'telephoneNumber',
                '555-01',
            ),
        );
    }

    public function test_a_type_with_no_substr_rule_has_no_substring_forms(): void
    {
        self::assertNull($this->subject->substringKey(
            'member',
            'cn=a,dc=foo,dc=bar',
        ));
        self::assertNull($this->subject->substringFragment(
            'member',
            'cn=a',
        ));
    }

    public function test_a_substr_rule_with_no_fragment_form_has_no_substring_fragment(): void
    {
        self::assertNull($this->subject->substringFragment(
            'dnSubstrings',
            'cn=a',
        ));
    }
}
