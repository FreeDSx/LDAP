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
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use PHPUnit\Framework\TestCase;

final class AnonBindRequestTest extends TestCase
{
    private AnonBindRequest $subject;

    protected function setUp(): void
    {
        $this->subject = new AnonBindRequest();
    }

    public function test_it_should_default_to_ldap_v3(): void
    {
        self::assertSame(
            3,
            $this->subject->getVersion(),
        );
    }

    public function test_it_should_have_an_empty_username_by_default(): void
    {
        self::assertSame(
            '',
            $this->subject->getUsername(),
        );
    }

    public function test_it_should_set_the_username(): void
    {
        $this->subject->setUsername('foo');

        self::assertSame(
            'foo',
            $this->subject->getUsername(),
        );
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        self::assertEquals(
            Asn1::application(0, Asn1::sequence(
                Asn1::integer(3),
                Asn1::octetString(''),
                Asn1::context(0, Asn1::octetString(''))
            )),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $anon = new AnonBindRequest('foo', 2);

        self::assertEquals(
            new AnonBindRequest('foo', 2),
            AnonBindRequest::fromAsn1($anon->toAsn1()),
        );
    }

    public function test_it_should_check_that_a_password_is_empty_properly(): void
    {
        self::assertNotInstanceOf(
            AnonBindRequest::class,
            AnonBindRequest::fromAsn1(
                (new SimpleBindRequest('foo', '0'))->toAsn1()
            )
        );
    }

    /**
     * @dataProvider malformedAsn1DataProvider
     */
    public function test_it_should_detect_invalid_asn1(AbstractType $type): void
    {
        $this->expectException(ProtocolException::class);

        $this->subject->fromAsn1($type);
    }

    /**
     * @return array<array<AbstractType>>
     */
    public static function malformedAsn1DataProvider(): array
    {
        return [
            [Asn1::sequence(
                Asn1::integer(3),
                Asn1::octetString('foo'),
                Asn1::context(3, Asn1::octetString('foo'))
            )],
            [Asn1::sequence(
                Asn1::octetString('foo'),
                Asn1::integer(2)
            )],
            [Asn1::sequence()],
            [Asn1::integer(2)],
        ];
    }
}
