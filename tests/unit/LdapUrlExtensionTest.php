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

namespace Tests\Unit\FreeDSx\Ldap;

use FreeDSx\Ldap\Exception\UrlParseException;
use FreeDSx\Ldap\LdapUrlExtension;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class LdapUrlExtensionTest extends TestCase
{
    private LdapUrlExtension $subject;

    protected function setUp(): void
    {
        $this->subject = new LdapUrlExtension('foo');
    }

    public function test_it_should_get_the_extension_name(): void
    {
        self::assertSame(
            'foo',
            $this->subject->getName(),
        );

        $this->subject->setName('bar');

        self::assertSame(
            'bar',
            $this->subject->getName(),
        );
    }

    public function test_it_should_get_the_extension_value(): void
    {
        self::assertNull($this->subject->getValue());

        $this->subject->setValue('bar');

        self::assertSame(
            'bar',
            $this->subject->getValue(),
        );
    }

    public function test_it_should_get_the_criticality(): void
    {
        self::assertFalse($this->subject->getIsCritical());

        $this->subject->setIsCritical(true);

        self::assertTrue($this->subject->getIsCritical());
    }

    public function test_it_should_parse_an_extension_with_only_a_name(): void
    {
        self::assertEquals(
            new LdapUrlExtension('foo'),
            LdapUrlExtension::parse('foo'),
        );
    }

    public function test_it_should_generate_a_string_extension_with_only_a_name(): void
    {
        self::assertSame(
            'foo',
            $this->subject->toString(),
        );
    }

    public function test_it_should_parse_an_extension_with_a_criticality(): void
    {
        self::assertEquals(
            new LdapUrlExtension(
                'foo',
                null,
                true,
            ),
            LdapUrlExtension::parse('!foo'),
        );
    }

    public function test_it_should_generate_a_string_extension_with_a_criticality(): void
    {
        $this->subject->setIsCritical(true);

        self::assertSame(
            '!foo',
            $this->subject->toString(),
        );
    }

    public function test_it_should_parse_an_extension_with_a_value(): void
    {
        self::assertEquals(
            new LdapUrlExtension(
                'foo',
                'bar',
            ),
            LdapUrlExtension::parse('foo=bar'),
        );
    }

    public function test_it_should_generate_a_string_extension_with_a_value(): void
    {
        $this->subject->setValue('bar');

        self::assertSame(
            'foo=bar',
            $this->subject->toString(),
        );
    }

    public function test_it_should_parse_an_extension_and_decode_it_if_needed(): void
    {
        self::assertEquals(
            new LdapUrlExtension(
                'e-bindname',
                'cn=Manager,dc=example,dc=com',
            ),
            LdapUrlExtension::parse('e-bindname=cn=Manager%2cdc=example%2cdc=com'),
        );
    }

    public function test_it_should_generate_a_string_extension_and_encode_it_if_needed(): void
    {
        $this->subject = new LdapUrlExtension(
            'e-bindname',
            'cn=Manager,dc=example,dc=com',
        );

        self::assertSame(
            'e-bindname=cn=Manager%2cdc=example%2cdc=com',
            $this->subject->toString(),
        );
    }

    public function test_it_should_parse_a_numeric_oid_extension_type(): void
    {
        self::assertEquals(
            new LdapUrlExtension(
                '1.3.6.1.4.1.1466.20037',
                'v',
            ),
            LdapUrlExtension::parse('1.3.6.1.4.1.1466.20037=v'),
        );
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function malformedExtensionProvider(): array
    {
        return [
            'a repeated criticality marker' => [
                '!!e-bindname',
            ],
            'a type with a leading hyphen' => [
                '-bindname=v',
            ],
            'a type with a leading digit' => [
                '1bindname=v',
            ],
            'an arc with a leading zero' => [
                '1.03.6=v',
            ],
            'a type holding a space' => [
                'e bindname=v',
            ],
            'an empty type' => [
                '=v',
            ],
        ];
    }

    #[DataProvider('malformedExtensionProvider')]
    public function test_it_should_reject_an_extension_type_that_is_not_an_oid(string $extension): void
    {
        $this->expectException(UrlParseException::class);

        LdapUrlExtension::parse($extension);
    }
}
