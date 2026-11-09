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

use DateTimeImmutable;
use DateTimeZone;
use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ForwardPasswordPolicyStateRequest;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\Request\ExtendedRequestDecoder;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\TrailingComponentTrait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class ExtendedRequestDecoderTest extends TestCase
{
    use ServerContainerTrait;
    use TrailingComponentTrait;

    private ExtendedRequestDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(ExtendedRequestDecoder::class);
        $this->context = new DecodeContext();
    }

    public function testItDecodesARequestWithNoValue(): void
    {
        $request = new ExtendedRequest('foo');

        self::assertEquals(
            $request,
            $this->subject->decode(
                $request->toAsn1(),
                $this->context,
            ),
        );
    }

    public function testItDecodesARequestWithAValue(): void
    {
        $request = new ExtendedRequest(
            'foo',
            'bar',
        );

        self::assertEquals(
            $request,
            $this->subject->decode(
                $request->toAsn1(),
                $this->context,
            ),
        );
    }

    public function testItIgnoresATrailingComponentItDoesNotRecognize(): void
    {
        $request = new ExtendedRequest(
            'foo',
            'bar',
        );

        self::assertEquals(
            $request,
            $this->subject->decode(
                self::withTrailingComponent($request->toAsn1()),
                $this->context,
            ),
        );
    }

    public function testItDecodesACancelIntoItsOwnType(): void
    {
        self::assertEquals(
            new CancelRequest(2),
            $this->subject->decode(
                (new CancelRequest(2))->toAsn1(),
                $this->context,
            ),
        );
    }

    public function testItDecodesAForwardedPasswordPolicyStateIntoItsOwnType(): void
    {
        $request = new ForwardPasswordPolicyStateRequest(
            'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
            [new DateTimeImmutable(
                '2026-01-01 00:00:00',
                new DateTimeZone('UTC'),
            )],
        );

        self::assertInstanceOf(
            ForwardPasswordPolicyStateRequest::class,
            $this->subject->decode(
                $request->toAsn1(),
                $this->context,
            ),
        );
    }

    public function testItLeavesAPasswordModifyForItsHandlerToDecode(): void
    {
        self::assertSame(
            ExtendedRequest::class,
            $this->subject->decode(
                Operations::passwordModify(
                    'cn=foo',
                    'old',
                    'new',
                )->toAsn1(),
                $this->context,
            )::class,
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
            'not a sequence' => [Asn1::octetString('foo')],
            'no request name' => [Asn1::sequence(Asn1::octetString('foo'))],
            'no components' => [Asn1::sequence()],
        ];
    }
}
