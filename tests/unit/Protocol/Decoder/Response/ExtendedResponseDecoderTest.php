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
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\Response\ExtendedResponseDecoder;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\ResultReferralsTrait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class ExtendedResponseDecoderTest extends TestCase
{
    use ResultReferralsTrait;
    use ServerContainerTrait;

    private ExtendedResponseDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(ExtendedResponseDecoder::class);
        $this->context = new DecodeContext();
    }

    public function testItDecodesTheResultNameAndValue(): void
    {
        self::assertEquals(
            new ExtendedResponse(
                new LdapResult(
                    0,
                    'dc=foo,dc=bar',
                    'foo',
                    new LdapUrl('foo'),
                    new LdapUrl('bar'),
                ),
                'foo',
                'bar',
            ),
            $this->subject->decode(
                Asn1::application(
                    24,
                    Asn1::sequence(
                        Asn1::enumerated(0),
                        Asn1::octetString('dc=foo,dc=bar'),
                        Asn1::octetString('foo'),
                        self::referralsField(
                            'ldap://foo',
                            'ldap://bar',
                        ),
                        Asn1::context(
                            10,
                            Asn1::octetString('foo'),
                        ),
                        Asn1::context(
                            11,
                            Asn1::octetString('bar'),
                        ),
                    ),
                ),
                $this->context,
            ),
        );
    }

    public function testItDecodesAResponseWithNoNameOrValue(): void
    {
        $response = $this->subject->decode(
            (new ExtendedResponse(new LdapResult(0)))->toAsn1(),
            $this->context,
        );

        self::assertSame(
            [null, null],
            [
                $response->getName(),
                $response->getValue(),
            ],
        );
    }
}
