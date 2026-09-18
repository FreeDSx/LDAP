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
        self::assertTrue($this->subject->links('member'));
        self::assertTrue($this->subject->links('owner'));
        self::assertTrue($this->subject->links('seeAlso'));
    }

    public function test_a_pointer_that_would_break_on_rename_is_declared(): void
    {
        self::assertTrue($this->subject->links('pwdPolicySubentry'));
    }

    public function test_a_type_inheriting_its_syntax_from_a_supertype_is_declared(): void
    {
        self::assertTrue($this->subject->links('roleOccupant'));
    }

    public function test_an_identity_that_need_not_exist_in_the_directory_is_not_declared(): void
    {
        self::assertFalse($this->subject->links('creatorsName'));
        self::assertFalse($this->subject->links('modifiersName'));
    }

    public function test_an_alias_target_which_may_dangle_is_not_declared(): void
    {
        self::assertFalse($this->subject->links('aliasedObjectName'));
    }

    public function test_the_supertype_of_the_declared_types_is_not_itself_declared(): void
    {
        self::assertFalse($this->subject->links('distinguishedName'));
    }

    public function test_it_resolves_a_type_named_by_any_of_its_names(): void
    {
        self::assertSame(
            $this->subject->links('MEMBER'),
            $this->subject->links('member'),
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
}
