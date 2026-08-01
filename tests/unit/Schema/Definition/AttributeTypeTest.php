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

namespace Tests\Unit\FreeDSx\Ldap\Schema\Definition;

use FreeDSx\Ldap\Schema\Definition\AttributeType;
use FreeDSx\Ldap\Schema\Definition\AttributeUsage;
use PHPUnit\Framework\TestCase;

final class AttributeTypeTest extends TestCase
{
    public function test_description_string_minimal(): void
    {
        $attr = new AttributeType(
            oid: '2.5.4.3',
            names: ['cn'],
        );

        self::assertSame(
            "( 2.5.4.3 NAME 'cn' )",
            $attr->toDescriptionString(),
        );
    }

    public function test_description_string_with_alias(): void
    {
        $attr = new AttributeType(
            oid: '2.5.4.3',
            names: ['cn', 'commonName'],
        );

        self::assertSame(
            "( 2.5.4.3 NAME ( 'cn' 'commonName' ) )",
            $attr->toDescriptionString(),
        );
    }

    public function test_description_string_with_all_string_fields(): void
    {
        $attr = new AttributeType(
            oid: '2.5.4.3',
            names: ['cn'],
            equalityOid: '2.5.13.2',
            orderingOid: '2.5.13.3',
            substringOid: '2.5.13.4',
            syntaxOid: '1.3.6.1.4.1.1466.115.121.1.15',
            superTypeOid: '2.5.4.41',
            desc: 'common name',
        );

        self::assertSame(
            "( 2.5.4.3 NAME 'cn' DESC 'common name' SUP 2.5.4.41 EQUALITY 2.5.13.2 ORDERING 2.5.13.3 SUBSTR 2.5.13.4 SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
            $attr->toDescriptionString(),
        );
    }

    public function test_description_string_with_boolean_flags(): void
    {
        $attr = new AttributeType(
            oid: '2.5.4.3',
            names: ['cn'],
            singleValue: true,
            collective: true,
        );

        self::assertSame(
            "( 2.5.4.3 NAME 'cn' SINGLE-VALUE COLLECTIVE )",
            $attr->toDescriptionString(),
        );
    }

    public function test_description_string_no_user_modification(): void
    {
        $attr = new AttributeType(
            oid: '2.5.18.1',
            names: ['createTimestamp'],
            noUserModification: true,
            usage: AttributeUsage::DirectoryOperation,
        );

        self::assertSame(
            "( 2.5.18.1 NAME 'createTimestamp' NO-USER-MODIFICATION USAGE directoryOperation )",
            $attr->toDescriptionString(),
        );
    }

    public function test_description_string_usage_user_applications_is_omitted(): void
    {
        $attr = new AttributeType(
            oid: '2.5.4.3',
            names: ['cn'],
            usage: AttributeUsage::UserApplications,
        );

        self::assertStringNotContainsString(
            'USAGE',
            $attr->toDescriptionString(),
        );
    }

    public function test_description_string_with_obsolete(): void
    {
        $attr = new AttributeType(
            oid: '2.5.4.3',
            names: ['cn'],
            obsolete: true,
        );

        self::assertSame(
            "( 2.5.4.3 NAME 'cn' OBSOLETE )",
            $attr->toDescriptionString(),
        );
    }

    public function test_an_attribute_is_not_confidential_by_default(): void
    {
        $attr = new AttributeType(
            oid: '2.5.4.3',
            names: ['cn'],
        );

        self::assertFalse($attr->isConfidential());
    }

    public function test_an_attribute_is_confidential_when_the_extension_is_set(): void
    {
        $attr = new AttributeType(
            oid: '2.5.4.35',
            names: ['userPassword'],
            extensions: [
                AttributeType::EXTENSION_CONFIDENTIAL => [AttributeType::EXTENSION_ENABLED_VALUE],
            ],
        );

        self::assertTrue($attr->isConfidential());
    }

    public function test_the_confidential_extension_round_trips_through_the_description_string(): void
    {
        $attr = new AttributeType(
            oid: '2.5.4.35',
            names: ['userPassword'],
            extensions: [
                AttributeType::EXTENSION_CONFIDENTIAL => [AttributeType::EXTENSION_ENABLED_VALUE],
            ],
        );

        self::assertSame(
            "( 2.5.4.35 NAME 'userPassword' X-CONFIDENTIAL 'TRUE' )",
            $attr->toDescriptionString(),
        );
    }
}
