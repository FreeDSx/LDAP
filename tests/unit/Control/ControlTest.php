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

namespace Tests\Unit\FreeDSx\Ldap\Control;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Control;
use PHPUnit\Framework\TestCase;

class ControlTest extends TestCase
{
    private Control $subject;

    protected function setUp(): void
    {
        $this->subject = new Control('foo');
    }

    public function test_it_should_get_the_control_type(): void
    {
        $this->subject->setTypeOid('bar');

        self::assertSame(
            'bar',
            $this->subject->getTypeOid(),
        );
    }

    public function test_it_should_get_the_control_value(): void
    {
        $this->subject->setValue('bar');

        self::assertSame(
            'bar',
            $this->subject->getValue(),
        );
    }

    public function test_it_should_get_the_criticality(): void
    {
        $this->subject->setCriticality(true);

        self::assertTrue(
            $this->subject->getCriticality(),
        );
    }

    public function test_it_should_have_a_string_representation_of_the_oid_type(): void
    {
        self::assertSame(
            'foo',
            (string) $this->subject,
        );
    }

    public function test_it_should_generate_correct_ASN1(): void
    {
        self::assertEquals(
            Asn1::sequence(
                Asn1::octetString('foo'),
                Asn1::boolean(false)
            ),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_should_be_constructed_from_ASN1(): void
    {
        $result = Control::fromAsn1(Asn1::sequence(
            Asn1::octetString('foobar'),
            Asn1::boolean(true)
        ));

        self::assertSame(
            'foobar',
            $result->getTypeOid(),
        );
        self::assertTrue(
            $result->getCriticality(),
        );
    }
}
