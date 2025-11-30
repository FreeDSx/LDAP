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

namespace Tests\Unit\FreeDSx\Ldap\Entry;

use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class RdnTest extends TestCase
{
    private Rdn $subject;

    protected function setUp(): void
    {
        $this->subject = new Rdn(
            'cn',
            'foo',
        );
    }

    public function test_it_should_get_the_name(): void
    {
        self::assertSame(
            'cn',
            $this->subject->getName(),
        );
    }

    public function test_it_should_get_the_value(): void
    {
        self::assertSame(
            'foo',
            $this->subject->getValue(),
        );
    }

    public function test_it_should_get_the_string_representation(): void
    {
        self::assertSame(
            'cn=foo',
            $this->subject->toString(),
        );
    }

    public function test_it_should_get_whether_it_is_multivalued(): void
    {
        self::assertFalse($this->subject->isMultivalued());
    }

    public function test_it_should_be_created_from_a_string_rdn(): void
    {
        $this->subject = Rdn::create('cn=foobar');

        self::assertSame(
            'cn',
            $this->subject->getName(),
        );
        self::assertSame(
            'foobar',
            $this->subject->getValue(),
        );
    }

    public function test_it_should_error_when_constructing_an_rdn_that_is_invalid(): void
    {
        $this->expectException(InvalidArgumentException::class);

        Rdn::create('foobar');
    }

    public function test_it_should_escape_an_rdn_value_with_leading_and_trailing_spaces(): void
    {
        self::assertSame(
            '\20foo\2c= bar\20',
            Rdn::escape(' foo,= bar '),
        );
    }

    public function test_it_should_escape_an_rdn_value_with_a_leading_pound_sign(): void
    {
        self::assertSame(
            '\23 foo\20',
            Rdn::escape('# foo '),
        );
    }

    public function test_it_should_escape_required_values(): void
    {
        self::assertSame(
            '\5cfoo \2b \22bar\22\2c \3e bar \3c foo\3b',
            Rdn::escape('\foo + "bar", > bar < foo;'),
        );
    }

    public function test_it_should_escape_all_characters(): void
    {
        self::assertSame(
            '\23\20\66\6f\6f\20',
            Rdn::escapeAll('# foo '),
        );
    }
}
