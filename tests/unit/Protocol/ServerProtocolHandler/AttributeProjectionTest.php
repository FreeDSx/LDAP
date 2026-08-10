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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\AttributeProjection;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaResource;
use PHPUnit\Framework\TestCase;

final class AttributeProjectionTest extends TestCase
{
    private Schema $schema;

    private Entry $entry;

    protected function setUp(): void
    {
        $this->schema = SchemaResource::Core->load();
        $this->entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
            new Attribute('userPassword', 'secret'),
            new Attribute('createTimestamp', '20260101000000Z'),
            new Attribute('modifyTimestamp', '20260102000000Z'),
            new Attribute('entryUUID', '11111111-2222-3333-4444-555555555555'),
        );
    }

    public function test_empty_selection_returns_only_user_attributes(): void
    {
        $projection = AttributeProjection::forRequest(
            [],
            false,
            $this->schema,
        );

        self::assertEqualsCanonicalizing(
            ['cn', 'sn', 'userPassword'],
            $this->attributeNames($projection->project($this->entry)),
        );
    }

    public function test_star_selector_returns_only_user_attributes(): void
    {
        $projection = AttributeProjection::forRequest(
            [new Attribute('*')],
            false,
            $this->schema,
        );

        $projected = $projection->project($this->entry);

        self::assertEqualsCanonicalizing(
            ['cn', 'sn', 'userPassword'],
            $this->attributeNames($projected),
        );
    }

    /**
     * RFC 4511 section 4.5.1.8 clause 2: "*" plus a named operational attribute returns both.
     */
    public function test_star_selector_also_returns_an_operational_attribute_named_alongside_it(): void
    {
        $projection = AttributeProjection::forRequest(
            [
                new Attribute('*'),
                new Attribute('entryUUID'),
            ],
            false,
            $this->schema,
        );

        self::assertEqualsCanonicalizing(
            ['cn', 'sn', 'userPassword', 'entryUUID'],
            $this->attributeNames($projection->project($this->entry)),
        );
    }

    public function test_star_and_plus_together_return_every_attribute(): void
    {
        $projection = AttributeProjection::forRequest(
            [
                new Attribute('*'),
                new Attribute('+'),
            ],
            false,
            $this->schema,
        );

        self::assertEqualsCanonicalizing(
            ['cn', 'sn', 'userPassword', 'createTimestamp', 'modifyTimestamp', 'entryUUID'],
            $this->attributeNames($projection->project($this->entry)),
        );
    }

    public function test_an_attribute_the_schema_does_not_define_counts_as_a_user_attribute(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Alice'),
            new Attribute('someCustomAttr', 'value'),
        );

        $projection = AttributeProjection::forRequest(
            [new Attribute('*')],
            false,
            $this->schema,
        );

        self::assertEqualsCanonicalizing(
            ['cn', 'someCustomAttr'],
            $this->attributeNames($projection->project($entry)),
        );
    }

    public function test_one_one_selector_strips_all_attributes(): void
    {
        $projection = AttributeProjection::forRequest(
            [new Attribute('1.1')],
            false,
            $this->schema,
        );

        $projected = $projection->project($this->entry);

        self::assertSame(
            [],
            $this->attributeNames($projected),
        );
        self::assertSame(
            'cn=Alice,dc=example,dc=com',
            $projected->getDn()->toString(),
        );
    }

    public function test_explicit_names_return_only_those_attributes(): void
    {
        $projection = AttributeProjection::forRequest(
            [
                new Attribute('cn'),
                new Attribute('sn'),
            ],
            false,
            $this->schema,
        );

        $projected = $projection->project($this->entry);

        self::assertEqualsCanonicalizing(
            ['cn', 'sn'],
            $this->attributeNames($projected),
        );
    }

    public function test_explicit_name_match_is_case_insensitive(): void
    {
        $projection = AttributeProjection::forRequest(
            [new Attribute('CN')],
            false,
            $this->schema,
        );

        $projected = $projection->project($this->entry);

        self::assertSame(
            ['cn'],
            $this->attributeNames($projected),
        );
    }

    public function test_plus_selector_returns_only_operational_attributes(): void
    {
        $projection = AttributeProjection::forRequest(
            [new Attribute('+')],
            false,
            $this->schema,
        );

        $projected = $projection->project($this->entry);

        self::assertEqualsCanonicalizing(
            ['createTimestamp', 'modifyTimestamp', 'entryUUID'],
            $this->attributeNames($projected),
        );
    }

    public function test_plus_selector_combines_with_explicit_user_attributes(): void
    {
        $projection = AttributeProjection::forRequest(
            [
                new Attribute('+'),
                new Attribute('cn'),
            ],
            false,
            $this->schema,
        );

        $projected = $projection->project($this->entry);

        self::assertEqualsCanonicalizing(
            ['cn', 'createTimestamp', 'modifyTimestamp', 'entryUUID'],
            $this->attributeNames($projected),
        );
    }

    public function test_plus_selector_returns_nothing_when_schema_does_not_know_any_operational_attrs(): void
    {
        $projection = AttributeProjection::forRequest(
            [new Attribute('+')],
            false,
            new Schema(),
        );

        $projected = $projection->project($this->entry);

        self::assertSame(
            [],
            $this->attributeNames($projected),
        );
    }

    public function test_types_only_drops_values_but_keeps_attribute_names(): void
    {
        $projection = AttributeProjection::forRequest(
            [new Attribute('*')],
            true,
            $this->schema,
        );

        $projected = $projection->project($this->entry);

        foreach ($projected->getAttributes() as $attribute) {
            self::assertSame(
                [],
                $attribute->getValues(),
            );
        }
        self::assertNotSame(
            [],
            $projected->getAttributes(),
        );
    }

    public function test_repeated_projection_returns_consistent_results(): void
    {
        $projection = AttributeProjection::forRequest(
            [new Attribute('+')],
            false,
            $this->schema,
        );

        $first = $this->attributeNames($projection->project($this->entry));
        $second = $this->attributeNames($projection->project($this->entry));

        self::assertSame(
            $first,
            $second,
        );
    }

    /**
     * @return string[]
     */
    private function attributeNames(Entry $entry): array
    {
        return array_map(
            static fn(Attribute $a): string => $a->getName(),
            $entry->getAttributes(),
        );
    }
}
