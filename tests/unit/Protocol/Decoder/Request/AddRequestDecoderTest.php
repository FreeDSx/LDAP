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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Decoder\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\Request\AddRequestDecoder;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\TrailingComponentTrait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class AddRequestDecoderTest extends TestCase
{
    use ServerContainerTrait;
    use TrailingComponentTrait;

    private AddRequestDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(AddRequestDecoder::class);
        $this->context = new DecodeContext();
    }

    public function testItDecodesTheEntryToAdd(): void
    {
        $add = new AddRequest(Entry::create(
            'cn=foo,dc=foo,dc=bar',
            ['cn' => 'foo', 'sn' => ['foo', 'bar']],
        ));

        self::assertEquals(
            $add,
            $this->subject->decode(
                $add->toAsn1(),
                $this->context,
            ),
        );
    }

    public function testItIgnoresTrailingComponentsItDoesNotRecognize(): void
    {
        $asn1 = self::withTrailingComponent(Asn1::application(
            8,
            Asn1::sequence(
                Asn1::octetString('cn=foo,dc=foo,dc=bar'),
                Asn1::sequenceOf(self::withTrailingComponent(Asn1::sequence(
                    Asn1::octetString('cn'),
                    Asn1::setOf(Asn1::octetString('foo')),
                ))),
            ),
        ));

        self::assertEquals(
            new AddRequest(Entry::create(
                'cn=foo,dc=foo,dc=bar',
                ['cn' => 'foo'],
            )),
            $this->subject->decode(
                $asn1,
                $this->context,
            ),
        );
    }

    public function testItRefusesAnAttributeWithNoValues(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('No values for attribute type "cn".');

        $this->subject->decode(
            Asn1::sequence(
                Asn1::octetString('cn=foo,dc=bar'),
                Asn1::sequenceOf(Asn1::sequence(
                    Asn1::octetString('cn'),
                    Asn1::setOf(),
                )),
            ),
            $this->context,
        );
    }

    /**
     * @param AbstractType<mixed> $type
     */
    #[DataProvider('malformedRequests')]
    public function testItRefusesAMalformedRequest(AbstractType $type): void
    {
        $this->expectException(ProtocolException::class);

        $this->subject->decode(
            $type,
            $this->context,
        );
    }

    /**
     * @return array<string, array{AbstractType<mixed>}>
     */
    public static function malformedRequests(): array
    {
        return [
            'an attribute list that is not a sequence' => [Asn1::sequence(
                Asn1::octetString('foo'),
                Asn1::integer(2),
            )],
            'not a sequence' => [Asn1::octetString('foo')],
            'values that are not a set' => [Asn1::sequence(
                Asn1::octetString('foo'),
                Asn1::sequence(Asn1::sequence(
                    Asn1::octetString('foo'),
                    Asn1::sequence(),
                )),
            )],
            'an attribute with no values component' => [Asn1::sequence(
                Asn1::octetString('foo'),
                Asn1::sequence(Asn1::sequence(Asn1::octetString('foo'))),
            )],
        ];
    }
}
