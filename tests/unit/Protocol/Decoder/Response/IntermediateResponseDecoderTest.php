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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Decoder\Response;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Response\IntermediateResponse;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncIdSet;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use FreeDSx\Ldap\Protocol\Decoder\Response\IntermediateResponseDecoder;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class IntermediateResponseDecoderTest extends TestCase
{
    use ServerContainerTrait;

    private IntermediateResponseDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(IntermediateResponseDecoder::class);
        $this->context = $this->fromContainer(DecodeContextFactory::class)->create();
    }

    public function testItDecodesTheNameAndValue(): void
    {
        self::assertEquals(
            new IntermediateResponse(
                'foo',
                'bar',
            ),
            $this->subject->decode(
                Asn1::application(
                    25,
                    Asn1::sequence(
                        Asn1::context(
                            0,
                            Asn1::octetString('foo'),
                        ),
                        Asn1::context(
                            1,
                            Asn1::octetString('bar'),
                        ),
                    ),
                ),
                $this->context,
            ),
        );
    }

    public function testItDecodesASyncInfoMessageAsItsTypedForm(): void
    {
        self::assertEquals(
            new SyncIdSet(
                ['foo', 'bar'],
                false,
                'omnomnom',
            ),
            $this->subject->decode(
                (new SyncIdSet(
                    ['foo', 'bar'],
                    false,
                    'omnomnom',
                ))->toAsn1(),
                $this->context,
            ),
        );
    }

    public function testItRefusesAResponseThatIsNotASequence(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The intermediate response is malformed');

        $this->subject->decode(
            Asn1::octetString('foo'),
            $this->context,
        );
    }
}
