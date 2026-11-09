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
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\Response\SearchResultReferenceDecoder;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class SearchResultReferenceDecoderTest extends TestCase
{
    use ServerContainerTrait;

    private SearchResultReferenceDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(SearchResultReferenceDecoder::class);
        $this->context = new DecodeContext();
    }

    public function testItDecodesTheReferrals(): void
    {
        self::assertEquals(
            [
                new LdapUrl('foo'),
                new LdapUrl('bar'),
            ],
            $this->subject->decode(
                Asn1::application(
                    19,
                    Asn1::sequence(
                        Asn1::octetString('ldap://foo'),
                        Asn1::octetString('ldap://bar'),
                    ),
                ),
                $this->context,
            )->getReferrals(),
        );
    }

    public function testItIgnoresAnUnusableReferralWhenAnotherCanBeUsed(): void
    {
        self::assertEquals(
            [new LdapUrl('foo')],
            $this->subject->decode(
                Asn1::sequence(
                    Asn1::octetString('ldap://foo/'),
                    Asn1::octetString('?bar'),
                ),
                $this->context,
            )->getReferrals(),
        );
    }

    public function testItRefusesReferralsWhenNoneCanBeUsed(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The search result reference holds no usable URI.');

        $this->subject->decode(
            Asn1::sequence(Asn1::octetString('?bar')),
            $this->context,
        );
    }

    public function testItRefusesAReferralThatIsNotAnOctetString(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The search result reference is malformed.');

        $this->subject->decode(
            Asn1::sequence(Asn1::integer(1)),
            $this->context,
        );
    }
}
