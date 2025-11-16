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

namespace Tests\Unit\FreeDSx\Ldap\Search\Filter;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filter\PresentFilter;
use PHPUnit\Framework\TestCase;

class PresentFilterTest extends TestCase
{
    private PresentFilter $subject;

    protected function setUp(): void
    {
        $this->subject = new PresentFilter('foo');
    }

    public function test_it_should_get_the_attribute_name(): void
    {
        self::assertSame(
            'foo',
            $this->subject->getAttribute(),
        );
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        self::assertEquals(
            Asn1::context(7, Asn1::octetString('foo')),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        self::assertEquals(
            (new PresentFilter('foo')),
            PresentFilter::fromAsn1((new PresentFilter('foo'))->toAsn1())
        );
    }

    public function test_it_should_get_the_string_filter_representation(): void
    {
        self::assertSame(
            '(foo=*)',
            $this->subject->toString(),
        );
    }

    public function test_it_should_have_a_filter_as_a_toString_representation(): void
    {
        self::assertSame(
            '(foo=*)',
            (string) $this->subject,
        );
    }
}
