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
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\Request\AbandonRequestDecoder;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class AbandonRequestDecoderTest extends TestCase
{
    use ServerContainerTrait;

    private AbandonRequestDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(AbandonRequestDecoder::class);
        $this->context = new DecodeContext();
    }

    public function testItDecodesTheMessageIdToAbandon(): void
    {
        self::assertEquals(
            new AbandonRequest(1),
            $this->subject->decode(
                Asn1::application(
                    16,
                    Asn1::integer(1),
                ),
                $this->context,
            ),
        );
    }

    public function testItRefusesAMessageIdThatIsNotAnInteger(): void
    {
        $this->expectException(ProtocolException::class);

        $this->subject->decode(
            Asn1::application(
                16,
                Asn1::octetString('foo'),
            ),
            $this->context,
        );
    }
}
