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
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use FreeDSx\Ldap\Protocol\Decoder\Request\CompareRequestDecoder;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\TrailingComponentTrait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class CompareRequestDecoderTest extends TestCase
{
    use ServerContainerTrait;
    use TrailingComponentTrait;

    private CompareRequestDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(CompareRequestDecoder::class);
        $this->context = $this->fromContainer(DecodeContextFactory::class)->create();
    }

    public function testItDecodesTheEntryAndTheAssertion(): void
    {
        $compare = new CompareRequest(
            'foo',
            new EqualityFilter(
                'foo',
                'bar',
            ),
        );

        self::assertEquals(
            $compare,
            $this->subject->decode(
                $compare->toAsn1(),
                $this->context,
            ),
        );
    }

    public function testItIgnoresTrailingComponentsItDoesNotRecognize(): void
    {
        $asn1 = self::withTrailingComponent(Asn1::application(
            14,
            Asn1::sequence(
                Asn1::octetString('dc=foo,dc=bar'),
                self::withTrailingComponent(Asn1::sequence(
                    Asn1::octetString('foo'),
                    Asn1::octetString('bar'),
                )),
            ),
        ));

        self::assertEquals(
            new CompareRequest(
                'dc=foo,dc=bar',
                new EqualityFilter(
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
            'not a sequence' => [Asn1::octetString('foo')],
            'no components' => [Asn1::sequence()],
            'no assertion' => [Asn1::sequence(Asn1::octetString('foo'))],
            'an empty assertion' => [Asn1::sequence(
                Asn1::octetString('foo'),
                Asn1::sequence(),
            )],
        ];
    }
}
