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
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\Response\BindResponseDecoder;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\ResultReferralsTrait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class BindResponseDecoderTest extends TestCase
{
    use ResultReferralsTrait;
    use ServerContainerTrait;

    private BindResponseDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(BindResponseDecoder::class);
        $this->context = new DecodeContext();
    }

    public function testItDecodesTheResultAndSaslCredentials(): void
    {
        self::assertEquals(
            new BindResponse(
                new LdapResult(
                    0,
                    'dc=foo,dc=bar',
                    'foo',
                    new LdapUrl('foo'),
                ),
                'creds',
            ),
            $this->subject->decode(
                Asn1::application(
                    1,
                    Asn1::sequence(
                        Asn1::enumerated(0),
                        Asn1::octetString('dc=foo,dc=bar'),
                        Asn1::octetString('foo'),
                        self::referralsField('ldap://foo'),
                        Asn1::context(
                            7,
                            Asn1::octetString('creds'),
                        ),
                    ),
                ),
                $this->context,
            ),
        );
    }

    public function testItDecodesAResponseWithNoSaslCredentials(): void
    {
        self::assertNull($this->subject->decode(
            (new BindResponse(new LdapResult(0)))->toAsn1(),
            $this->context,
        )->getSaslCredentials());
    }
}
