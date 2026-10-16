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

namespace Tests\Unit\FreeDSx\Ldap\Protocol;

use FreeDSx\Asn1\Encoder\EncoderOptions;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\NullType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use Generator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class LdapEncoderTest extends TestCase
{
    private LdapEncoder $subject;

    protected function setUp(): void
    {
        $this->subject = new LdapEncoder();
    }

    #[DataProvider('applicationTagProvider')]
    public function test_it_decodes_the_ldap_application_tags_as_their_universal_types(
        string $bytes,
        string $expectedType,
    ): void {
        self::assertSame(
            $expectedType,
            $this->subject->decode($bytes)::class,
        );
    }

    public static function applicationTagProvider(): Generator
    {
        yield 'bind request as a sequence' => [
            "\x60\x00",
            SequenceType::class,
        ];
        yield 'unbind request as a null' => [
            "\x42\x00",
            NullType::class,
        ];
        yield 'delete request as an octet string' => [
            "\x4a\x03foo",
            OctetStringType::class,
        ];
        yield 'abandon request as an integer' => [
            "\x50\x01\x05",
            IntegerType::class,
        ];
        yield 'intermediate response as a sequence' => [
            "\x79\x00",
            SequenceType::class,
        ];
    }

    public function test_it_leaves_an_unmapped_application_tag_incomplete(): void
    {
        self::assertInstanceOf(
            IncompleteType::class,
            $this->subject->decode("\x5e\x01x"),
        );
    }

    public function test_it_keeps_the_options_it_is_constructed_with(): void
    {
        $options = new EncoderOptions(maxLength: 10);

        self::assertSame(
            $options,
            (new LdapEncoder($options))->getOptions(),
        );
    }
}
