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
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

final class CancelRequestTest extends TestCase
{
    private CancelRequest $subject;

    protected function setUp(): void
    {
        $this->subject = new CancelRequest(1);
    }

    public function test_it_should_set_the_message_id(): void
    {
        self::assertSame(
            1,
            $this->subject->getMessageId(),
        );

        $this->subject->setMessageId(2);

        self::assertSame(
            2,
            $this->subject->getMessageId(),
        );
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            Asn1::application(23, Asn1::sequence(
                Asn1::context(0, Asn1::octetString(ExtendedRequest::OID_CANCEL)),
                Asn1::context(1, Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::integer(1)
                ))))
            )),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        self::assertEquals(
            new CancelRequest(2),
            CancelRequest::fromAsn1((new CancelRequest(2))->toAsn1()),
        );
    }

    /**
     * @dataProvider malformedAsn1DataProvider
     */
    public function test_it_should_detect_invalid_asn1_from_asn1(AbstractType $type): void
    {
        $this->expectException(ProtocolException::class);

        CancelRequest::fromAsn1($type);
    }

    /**
     * @return array<array<AbstractType>>
     */
    public static function malformedAsn1DataProvider(): array
    {
        $req = new ExtendedRequest('foo', Asn1::octetString('foo'));

        return [
            [$req->toAsn1()],
            [$req->setValue(Asn1::sequence())->toAsn1()],
            [$req->setValue(Asn1::sequence(Asn1::octetString('bar')))->toAsn1()]
        ];
    }
}
