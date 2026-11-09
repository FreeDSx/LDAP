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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Decoder\Filter;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\Filter\FilterDecodeRun;
use FreeDSx\Ldap\Protocol\Decoder\Filter\FilterDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Filter\PresentFilterDecoder;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\ReceivedAsn1Trait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class PresentFilterDecoderTest extends TestCase
{
    use ReceivedAsn1Trait;
    use ServerContainerTrait;

    private PresentFilterDecoder $subject;

    private FilterDecodeRun $run;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(PresentFilterDecoder::class);
        $this->run = new FilterDecodeRun(
            new DecodeContext(),
            $this->fromContainer(FilterDecoder::class),
        );
    }

    public function testItDecodesTheAttribute(): void
    {
        self::assertEquals(
            Filters::present('cn'),
            $this->subject->decode(
                self::received(Filters::present('cn')->toAsn1()),
                $this->run,
            ),
        );
    }

    public function testItDecodesAPresentFilterThatIsAlreadyDecoded(): void
    {
        self::assertEquals(
            Filters::present('cn'),
            $this->subject->decode(
                Filters::present('cn')->toAsn1(),
                $this->run,
            ),
        );
    }

    public function testItRefusesAnAttributeThatIsNotAnOctetString(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The present filter is malformed');

        $this->subject->decode(
            Asn1::context(
                7,
                Asn1::integer(1),
            ),
            $this->run,
        );
    }
}
