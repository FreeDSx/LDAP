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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Decoder\Control;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\Control\ProxyAuthorizationControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class ProxyAuthorizationControlDecoderTest extends TestCase
{
    use ServerContainerTrait;

    private ProxyAuthorizationControlDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(ProxyAuthorizationControlDecoder::class);
        $this->context = $this->fromContainer(DecodeContextFactory::class)->create();
    }

    public function testItDecodesTheRawValueAsTheAuthzId(): void
    {
        $control = $this->subject->decode(
            Asn1::sequence(
                Asn1::octetString(Control::OID_PROXY_AUTHORIZATION),
                Asn1::boolean(true),
                Asn1::octetString('u:bob'),
            ),
            $this->context,
        );

        self::assertSame(
            ['u:bob', 'u:bob', true, Control::OID_PROXY_AUTHORIZATION],
            [
                $control->getRawAuthzId(),
                $control->getAuthzId()->toString(),
                $control->getCriticality(),
                $control->getTypeOid(),
            ],
        );
    }

    public function testItKeepsAReceivedCriticalityOfFalse(): void
    {
        self::assertFalse($this->subject->decode(
            Asn1::sequence(
                Asn1::octetString(Control::OID_PROXY_AUTHORIZATION),
                Asn1::boolean(false),
                Asn1::octetString('u:bob'),
            ),
            $this->context,
        )->getCriticality());
    }

    public function testItDecodesAnEmptyValueAsTheAnonymousIdentity(): void
    {
        self::assertSame(
            '',
            $this->subject->decode(
                Asn1::sequence(
                    Asn1::octetString(Control::OID_PROXY_AUTHORIZATION),
                    Asn1::boolean(true),
                    Asn1::octetString(''),
                ),
                $this->context,
            )->getRawAuthzId(),
        );
    }

    public function testItRefusesAControlWithoutAValue(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The proxied authorization control must have a value.');

        $this->subject->decode(
            Asn1::sequence(
                Asn1::octetString(Control::OID_PROXY_AUTHORIZATION),
                Asn1::boolean(true),
            ),
            $this->context,
        );
    }

    public function testItDefersAMalformedAuthzIdUntilItIsRead(): void
    {
        $control = $this->subject->decode(
            Asn1::sequence(
                Asn1::octetString(Control::OID_PROXY_AUTHORIZATION),
                Asn1::boolean(true),
                Asn1::octetString('mail:bob@example.com'),
            ),
            $this->context,
        );

        self::assertSame(
            'mail:bob@example.com',
            $control->getRawAuthzId(),
        );

        $this->expectException(InvalidArgumentException::class);

        $control->getAuthzId();
    }
}
