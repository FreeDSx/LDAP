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
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use FreeDSx\Ldap\Protocol\Decoder\Request\BindRequestDecoder;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class BindRequestDecoderTest extends TestCase
{
    use ServerContainerTrait;

    private BindRequestDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(BindRequestDecoder::class);
        $this->context = $this->fromContainer(DecodeContextFactory::class)->create();
    }

    public function testItDecodesASimpleBind(): void
    {
        $bind = new SimpleBindRequest(
            'foo',
            'bar',
        );

        self::assertEquals(
            $bind,
            $this->subject->decode(
                $bind->toAsn1(),
                $this->context,
            ),
        );
    }

    public function testItDecodesAnAnonymousBind(): void
    {
        $bind = new AnonBindRequest(
            'foo',
            2,
        );

        self::assertEquals(
            $bind,
            $this->subject->decode(
                $bind->toAsn1(),
                $this->context,
            ),
        );
    }

    public function testAPasswordOfZeroIsNotAnAnonymousBind(): void
    {
        self::assertNotInstanceOf(
            AnonBindRequest::class,
            $this->subject->decode(
                (new SimpleBindRequest(
                    'foo',
                    '0',
                ))->toAsn1(),
                $this->context,
            ),
        );
    }

    public function testItDecodesASaslBindWithOnlyAMechanism(): void
    {
        $result = $this->subject->decode(
            (new SaslBindRequest('PLAIN'))->toAsn1(),
            $this->context,
        );

        self::assertInstanceOf(
            SaslBindRequest::class,
            $result,
        );
        self::assertSame(
            ['PLAIN', null],
            [$result->getMechanism(), $result->getCredentials()],
        );
    }

    public function testItDecodesASaslBindWithCredentials(): void
    {
        $result = $this->subject->decode(
            (new SaslBindRequest(
                'PLAIN',
                "\x00user\x00pass",
            ))->toAsn1(),
            $this->context,
        );

        self::assertInstanceOf(
            SaslBindRequest::class,
            $result,
        );
        self::assertSame(
            ['PLAIN', "\x00user\x00pass"],
            [$result->getMechanism(), $result->getCredentials()],
        );
    }

    public function testItKeepsTheDeclaredVersionOfASaslBind(): void
    {
        self::assertSame(
            2,
            $this->subject->decode(
                (new SaslBindRequest('PLAIN'))->setVersion(2)->toAsn1(),
                $this->context,
            )->getVersion(),
        );
    }

    public function testItRefusesASaslMechanismThatIsNotAnOctetString(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The SASL mechanism in the bind request is malformed.');

        $this->subject->decode(
            Asn1::application(
                0,
                Asn1::sequence(
                    Asn1::integer(3),
                    Asn1::octetString(''),
                    Asn1::context(
                        3,
                        Asn1::sequence(Asn1::integer(99)),
                    ),
                ),
            ),
            $this->context,
        );
    }

    public function testItRefusesAnAuthenticationChoiceItDoesNotSupport(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The auth choice tag 1 in the bind request is not supported.');

        $this->subject->decode(
            Asn1::application(
                0,
                Asn1::sequence(
                    Asn1::integer(3),
                    Asn1::octetString(''),
                    Asn1::context(
                        1,
                        Asn1::octetString(''),
                    ),
                ),
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
            'SASL credentials that are not a sequence' => [Asn1::sequence(
                Asn1::integer(3),
                Asn1::octetString('foo'),
                Asn1::context(
                    3,
                    Asn1::octetString('foo'),
                ),
            )],
            'a version that is not an integer' => [Asn1::sequence(
                Asn1::octetString('foo'),
                Asn1::integer(2),
            )],
            'no components' => [Asn1::sequence()],
            'not a sequence' => [Asn1::integer(2)],
            'no authentication choice' => [Asn1::sequence(
                Asn1::octetString('foo'),
                Asn1::integer(3),
            )],
        ];
    }
}
