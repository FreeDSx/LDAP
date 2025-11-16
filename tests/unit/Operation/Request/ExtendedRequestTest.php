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

namespace Tests\Unit\FreeDSx\Ldap\Operation\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use PHPUnit\Framework\TestCase;

final class ExtendedRequestTest extends TestCase
{
    private ExtendedRequest $subject;

    protected function setUp(): void
    {
        $this->subject = new ExtendedRequest(ExtendedRequest::OID_START_TLS);;
    }

    public function test_it_should_get_the_extended_request_name(): void
    {
        self::assertSame(
            ExtendedRequest::OID_START_TLS,
            $this->subject->getName(),
        );

        $this->subject->setName('foo');

        self::assertSame(
            'foo',
            $this->subject->getName(),
        );
    }

    public function test_it_should_get_the_extended_request_value(): void
    {
        $this->subject->setValue('foo');

        self::assertSame(
            'foo',
            $this->subject->getValue(),
        );
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        self::assertEquals(
            Asn1::application(23, Asn1::sequence(
                Asn1::context(0, Asn1::octetString(ExtendedRequest::OID_START_TLS))
            )),
            $this->subject->toAsn1(),
        );

        $this->subject->setValue('foo');

        self::assertEquals(
            Asn1::application(23, Asn1::sequence(
                Asn1::context(0, Asn1::octetString(ExtendedRequest::OID_START_TLS)),
                Asn1::context(1, Asn1::octetString('foo'))
            )),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_should_be_constructed_from_asn1_with_no_value(): void
    {
        $request = new ExtendedRequest('foo');

        self::assertEquals(
            $request,
            ExtendedRequest::fromAsn1($request->toAsn1()),
        );
    }

    public function test_it_should_be_constructed_from_asn1_with_a_value(): void
    {
        $request = new ExtendedRequest('foo', 'bar');

        self::assertEquals(
            $request,
            ExtendedRequest::fromAsn1($request->toAsn1()),
        );
    }

    /**
     * @dataProvider malformedAsn1DataProvider
     */
    public function test_it_should_detect_invalid_asn1(AbstractType $type): void
    {
        $this->expectException(ProtocolException::class);

        ExtendedRequest::fromAsn1($type);
    }

    /**
     * @return array<array<AbstractType>>
     */
    public static function malformedAsn1DataProvider(): array
    {
        return [
            [Asn1::octetString('foo')],
            [Asn1::sequence(Asn1::octetString('foo'))],
            [Asn1::sequence()],
        ];
    }
}
