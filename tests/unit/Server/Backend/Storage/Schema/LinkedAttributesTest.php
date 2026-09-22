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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Schema\Definition\AttributeType;
use FreeDSx\Ldap\Schema\Definition\ObjectClass;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use PHPUnit\Framework\TestCase;

final class LinkedAttributesTest extends TestCase
{
    private LinkedAttributes $subject;

    protected function setUp(): void
    {
        $this->subject = new LinkedAttributes(
            SchemaResource::Core->load()->merge(SchemaResource::PasswordPolicy->load()),
        );
    }

    public function test_the_core_schema_declares_the_dn_valued_group_attributes(): void
    {
        self::assertTrue($this->links('member'));
        self::assertTrue($this->links('owner'));
        self::assertTrue($this->links('seeAlso'));
    }

    public function test_a_pointer_that_would_break_on_rename_is_declared(): void
    {
        self::assertTrue($this->links('pwdPolicySubentry'));
    }

    public function test_a_type_inheriting_its_syntax_from_a_supertype_is_declared(): void
    {
        self::assertTrue($this->links('roleOccupant'));
    }

    public function test_an_identity_that_need_not_exist_in_the_directory_is_not_declared(): void
    {
        self::assertFalse($this->links('creatorsName'));
        self::assertFalse($this->links('modifiersName'));
    }

    public function test_an_alias_target_which_may_dangle_is_not_declared(): void
    {
        self::assertFalse($this->links('aliasedObjectName'));
    }

    public function test_the_supertype_of_the_declared_types_is_not_itself_declared(): void
    {
        self::assertFalse($this->links('distinguishedName'));
    }

    public function test_an_option_bearing_form_is_not_declared(): void
    {
        self::assertFalse($this->links('member;lang-en'));
    }

    public function test_it_resolves_a_type_named_by_any_of_its_names(): void
    {
        self::assertSame(
            $this->links('MEMBER'),
            $this->links('member'),
        );
    }

    public function test_it_reports_the_declared_names_lowercased(): void
    {
        self::assertContains(
            'member',
            $this->subject->names(),
        );
        self::assertContains(
            'pwdpolicysubentry',
            $this->subject->names(),
        );
    }

    public function test_the_shipped_schema_requires_no_linked_attribute(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->assertNoneRequired();
    }

    /**
     * A removal takes every link naming the entry with it, which no object class requiring one could survive.
     */
    public function test_an_object_class_requiring_a_linked_attribute_is_refused(): void
    {
        $subject = new LinkedAttributes(
            SchemaResource::Core->load()->addObjectClass(new ObjectClass(
                '1.200',
                ['strictGroup'],
                must: ['member'],
            )),
        );

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('strictGroup');

        $subject->assertNoneRequired();
    }

    public function test_the_core_schema_declares_the_group_membership_backlink(): void
    {
        self::assertTrue($this->subject->isBacklink(new Attribute('memberOf')));
        self::assertSame(
            'member',
            $this->subject->linkedBy('memberOf'),
        );
    }

    public function test_a_backlink_is_resolved_however_it_is_named(): void
    {
        self::assertSame(
            'member',
            $this->subject->linkedBy('MEMBEROF'),
        );
    }

    public function test_an_option_bearing_backlink_is_not_declared(): void
    {
        self::assertFalse($this->subject->isBacklink(new Attribute('memberOf;lang-en')));
    }

    public function test_a_linked_attribute_is_not_itself_a_backlink(): void
    {
        self::assertFalse($this->subject->isBacklink(new Attribute('member')));
        self::assertNull($this->subject->linkedBy('member'));
    }

    public function test_it_reports_the_backlink_reversing_each_linked_name(): void
    {
        self::assertSame(
            ['memberof'],
            $this->subject->backlinks()->reversing('member'),
        );
        self::assertSame(
            ['member'],
            $this->subject->backlinks()->linkedNames(),
        );
    }

    public function test_both_ends_of_a_link_are_held_apart_from_the_entry(): void
    {
        self::assertTrue($this->subject->heldApart(new Attribute('member')));
        self::assertTrue($this->subject->heldApart(new Attribute('memberOf')));
        self::assertFalse($this->subject->heldApart(new Attribute('cn')));
    }

    public function test_the_shipped_schema_derives_every_backlink_it_declares(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->assertBacklinksAreDerivable();
    }

    public function test_a_backlink_reversing_an_attribute_that_is_not_linked_is_refused(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('dangling');

        $this->derivableFor(
            'dangling',
            'cn',
            noUserModification: true,
        );
    }

    public function test_a_backlink_that_is_itself_linked_is_refused(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('bothWays');

        $this->derivableFor(
            'bothWays',
            'owner',
            noUserModification: true,
            linked: true,
        );
    }

    public function test_more_than_one_backlink_may_reverse_the_same_attribute(): void
    {
        $subject = new LinkedAttributes(
            SchemaResource::Core->load()->addAttributeType(new AttributeType(
                '1.400',
                ['isMemberOf'],
                noUserModification: true,
                extensions: [AttributeType::EXTENSION_LINKED_BY => ['member']],
            )),
        );
        $subject->assertBacklinksAreDerivable();

        self::assertEqualsCanonicalizing(
            ['memberof', 'ismemberof'],
            $subject->backlinks()->reversing('member'),
        );
        self::assertSame(
            ['member'],
            $subject->backlinks()->linkedNames(),
        );
    }

    public function test_a_backlink_is_read_under_one_of_its_names_only(): void
    {
        $subject = new LinkedAttributes(
            SchemaResource::Core->load()->addAttributeType(new AttributeType(
                '1.500',
                ['ownedBy', 'ownedByAlias'],
                noUserModification: true,
                extensions: [AttributeType::EXTENSION_LINKED_BY => ['owner']],
            )),
        );

        self::assertSame(
            ['ownedby'],
            $subject->backlinks()->reversing('owner'),
        );
        // Either name still resolves, so a filter naming the alias is answered from the same rows.
        self::assertSame(
            'owner',
            $subject->backlinks()->linkedBy('ownedByAlias'),
        );
    }

    public function test_a_backlink_a_client_could_write_is_refused(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('writable');

        $this->derivableFor(
            'writable',
            'owner',
            noUserModification: false,
        );
    }

    public function test_a_schema_declaring_none_is_empty(): void
    {
        $subject = new LinkedAttributes(
            (new Schema())->addAttributeType(new AttributeType(
                '1.100',
                ['plain'],
            )),
        );

        self::assertTrue($subject->isEmpty());
        self::assertSame(
            [],
            $subject->names(),
        );
    }

    public function test_the_core_schema_is_not_empty(): void
    {
        self::assertFalse($this->subject->isEmpty());
    }

    private function derivableFor(
        string $name,
        string $reverses,
        bool $noUserModification,
        bool $linked = false,
    ): void {
        $extensions = [AttributeType::EXTENSION_LINKED_BY => [$reverses]];

        if ($linked) {
            $extensions[AttributeType::EXTENSION_LINKED] = [AttributeType::EXTENSION_ENABLED_VALUE];
        }
        $subject = new LinkedAttributes(
            SchemaResource::Core->load()->addAttributeType(new AttributeType(
                '1.300',
                [$name],
                noUserModification: $noUserModification,
                extensions: $extensions,
            )),
        );

        $subject->assertBacklinksAreDerivable();
    }

    private function links(string $description): bool
    {
        return $this->subject->links(new Attribute($description));
    }
}
