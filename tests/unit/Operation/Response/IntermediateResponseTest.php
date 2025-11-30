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

namespace Tests\Unit\FreeDSx\Ldap\Operation\Response;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Operation\Response\IntermediateResponse;
use PHPUnit\Framework\TestCase;

final class IntermediateResponseTest extends TestCase
{
    private IntermediateResponse $subject;

    protected function setUp(): void
    {
        $this->subject = new IntermediateResponse(
            'foo',
            'bar',
        );
    }

    public function test_it_should_get_the_value(): void
    {
        self::assertSame(
            'bar',
            $this->subject->getValue(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $this->subject = IntermediateResponse::fromAsn1(Asn1::application(25, Asn1::sequence(
            Asn1::context(0, Asn1::octetString('foo')),
            Asn1::context(1, Asn1::octetString('bar')),
        )));

        self::assertSame(
            'foo',
            $this->subject->getName(),
        );
        self::assertSame(
            'bar',
            $this->subject->getValue(),
        );
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        self::assertEquals(
            Asn1::application(25, Asn1::sequence(
                Asn1::context(0, Asn1::octetString('foo')),
                Asn1::context(1, Asn1::octetString('bar')),
            )),
            $this->subject->toAsn1(),
        );
    }
}
