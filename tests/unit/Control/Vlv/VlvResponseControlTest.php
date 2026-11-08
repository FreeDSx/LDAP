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

namespace Tests\Unit\FreeDSx\Ldap\Control\Vlv;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\EnumeratedType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Vlv\VlvResponseControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class VlvResponseControlTest extends TestCase
{
    private VlvResponseControl $subject;

    protected function setUp(): void
    {
        $this->subject = new VlvResponseControl(
            offset: 10,
            count: 9,
            result: 0,
        );
    }

    public function test_it_should_get_the_offset(): void
    {
        self::assertSame(
            10,
            $this->subject->getOffset(),
        );
    }

    public function test_it_should_get_the_count(): void
    {
        self::assertSame(
            9,
            $this->subject->getCount(),
        );
    }

    public function test_it_should_get_the_context_id(): void
    {
        self::assertNull($this->subject->getContextId());
    }

    public function test_it_should_get_the_result(): void
    {
        self::assertSame(
            0,
            $this->subject->getResult(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            new VlvResponseControl(1, 300, 0, 'foo'),
            VlvResponseControl::fromAsn1(Asn1::sequence(
                Asn1::octetString(Control::OID_VLV_RESPONSE),
                Asn1::boolean(false),
                Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::integer(1),
                    Asn1::integer(300),
                    Asn1::enumerated(0),
                    Asn1::octetString('foo'),
                ))),
            ))->setValue(null),
        );
    }

    #[DataProvider('wideFieldProvider')]
    public function test_a_field_wider_than_an_integer_is_refused_as_malformed(
        SequenceType $value,
        string $message,
    ): void {
        $encoder = new LdapEncoder();

        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage($message);

        VlvResponseControl::fromAsn1(Asn1::sequence(
            Asn1::octetString(Control::OID_VLV_RESPONSE),
            Asn1::octetString($encoder->encode($value)),
        ));
    }

    /**
     * @return iterable<string, array{SequenceType, string}>
     */
    public static function wideFieldProvider(): iterable
    {
        yield 'target position' => [
            Asn1::sequence(
                Asn1::integer('18446744073709551616'),
                Asn1::integer(300),
                Asn1::enumerated(0),
            ),
            'The VLV response target position is not an integer.',
        ];
        yield 'content count' => [
            Asn1::sequence(
                Asn1::integer(1),
                Asn1::integer('18446744073709551616'),
                Asn1::enumerated(0),
            ),
            'The VLV response content count is not an integer.',
        ];
        yield 'result' => [
            Asn1::sequence(
                Asn1::integer(1),
                Asn1::integer(300),
                new EnumeratedType('18446744073709551616'),
            ),
            'The VLV response result is not an integer.',
        ];
    }
}
