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
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\Request\ModifyRequestDecoder;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\TrailingComponentTrait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class ModifyRequestDecoderTest extends TestCase
{
    use ServerContainerTrait;
    use TrailingComponentTrait;

    private ModifyRequestDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(ModifyRequestDecoder::class);
        $this->context = new DecodeContext();
    }

    public function testItDecodesTheEntryAndItsChanges(): void
    {
        $modify = new ModifyRequest(
            'foo',
            Change::add(
                'foo',
                'bar',
            ),
            Change::delete(
                'bar',
                'foo',
            ),
            Change::replace(
                'foobar',
                'foo',
            ),
        );

        self::assertEquals(
            $modify,
            $this->subject->decode(
                $modify->toAsn1(),
                $this->context,
            ),
        );
    }

    public function testItIgnoresTrailingComponentsItDoesNotRecognize(): void
    {
        $asn1 = self::withTrailingComponent(Asn1::application(
            6,
            Asn1::sequence(
                Asn1::octetString('cn=foo,dc=foo,dc=bar'),
                Asn1::sequenceOf(self::withTrailingComponent(Asn1::sequence(
                    Asn1::enumerated(Change::TYPE_REPLACE),
                    self::withTrailingComponent(Asn1::sequence(
                        Asn1::octetString('foo'),
                        Asn1::setOf(Asn1::octetString('bar')),
                    )),
                ))),
            ),
        ));

        self::assertEquals(
            new ModifyRequest(
                'cn=foo,dc=foo,dc=bar',
                Change::replace(
                    'foo',
                    'bar',
                ),
            ),
            $this->subject->decode(
                $asn1,
                $this->context,
            ),
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
            'a DN that is not an octet string' => [Asn1::sequence(
                Asn1::integer(1),
                Asn1::sequence(),
            )],
            'a change list in a set' => [Asn1::set(
                Asn1::octetString('dc=foo'),
                Asn1::sequence(),
            )],
            'attribute values that are not a set' => [Asn1::sequence(
                Asn1::octetString('foo'),
                Asn1::sequence(Asn1::sequence(
                    Asn1::enumerated(2),
                    Asn1::sequence(
                        Asn1::octetString('foo'),
                        Asn1::sequence(Asn1::octetString('bar')),
                    ),
                )),
            )],
            'a partial attribute without a description' => [Asn1::sequence(
                Asn1::octetString('foo'),
                Asn1::sequence(Asn1::sequence(
                    Asn1::enumerated(2),
                    Asn1::sequence(Asn1::setOf(Asn1::octetString('bar'))),
                )),
            )],
            'a change type that is not an enumerated' => [Asn1::sequence(
                Asn1::octetString('foo'),
                Asn1::sequence(Asn1::sequence(
                    Asn1::integer(999),
                    Asn1::sequence(Asn1::setOf(Asn1::octetString('bar'))),
                )),
            )],
        ];
    }
}
