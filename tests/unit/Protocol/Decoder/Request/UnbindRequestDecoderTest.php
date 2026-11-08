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
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use FreeDSx\Ldap\Protocol\Decoder\Request\UnbindRequestDecoder;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class UnbindRequestDecoderTest extends TestCase
{
    use ServerContainerTrait;

    private UnbindRequestDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(UnbindRequestDecoder::class);
        $this->context = $this->fromContainer(DecodeContextFactory::class)->create();
    }

    public function testItDecodesAnUnbind(): void
    {
        self::assertEquals(
            new UnbindRequest(),
            $this->subject->decode(
                Asn1::null(),
                $this->context,
            ),
        );
    }

    public function testItRefusesAnUnbindThatIsNotNull(): void
    {
        $this->expectException(ProtocolException::class);

        $this->subject->decode(
            Asn1::octetString('foo'),
            $this->context,
        );
    }
}
