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
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\EnumeratedType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\Response\ModifyResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use FreeDSx\Ldap\Protocol\Decoder\Response\LdapResultDecoder;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\ResultReferralsTrait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class LdapResultDecoderTest extends TestCase
{
    use ResultReferralsTrait;
    use ServerContainerTrait;

    /**
     * @var LdapResultDecoder<SearchResultDone>
     */
    private LdapResultDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = new LdapResultDecoder(SearchResultDone::class);
        $this->context = $this->fromContainer(DecodeContextFactory::class)->create();
    }

    public function testItDecodesTheResultCodeDnDiagnosticAndReferrals(): void
    {
        self::assertEquals(
            new SearchResultDone(
                0,
                'dc=foo,dc=bar',
                'foo',
                new LdapUrl('foo'),
                new LdapUrl('bar'),
            ),
            $this->subject->decode(
                Asn1::sequence(
                    Asn1::enumerated(0),
                    Asn1::octetString('dc=foo,dc=bar'),
                    Asn1::octetString('foo'),
                    self::referralsField(
                        'ldap://foo',
                        'ldap://bar',
                    ),
                ),
                $this->context,
            ),
        );
    }

    public function testItBuildsTheResultClassItIsGiven(): void
    {
        self::assertInstanceOf(
            ModifyResponse::class,
            (new LdapResultDecoder(ModifyResponse::class))->decode(
                (new ModifyResponse(0))->toAsn1(),
                $this->context,
            ),
        );
    }

    public function testItIgnoresAnUnusableReferralWhenAnotherCanBeUsed(): void
    {
        self::assertEquals(
            [new LdapUrl('foo')],
            $this->subject->decode(
                Asn1::sequence(
                    Asn1::enumerated(0),
                    Asn1::octetString('dc=foo,dc=bar'),
                    Asn1::octetString('foo'),
                    self::referralsField(
                        'ldap://foo',
                        'bar',
                    ),
                ),
                $this->context,
            )->getReferrals(),
        );
    }

    public function testItDecodesTheReferralsOfEveryReferralsFieldInTheOrderSent(): void
    {
        self::assertEquals(
            [
                new LdapUrl('foo'),
                new LdapUrl('bar'),
                new LdapUrl('baz'),
            ],
            $this->subject->decode(
                Asn1::sequence(
                    Asn1::enumerated(0),
                    Asn1::octetString('dc=foo,dc=bar'),
                    Asn1::octetString('foo'),
                    self::referralsField(
                        'ldap://foo',
                        'ldap://bar',
                    ),
                    self::referralsField('ldap://baz'),
                ),
                $this->context,
            )->getReferrals(),
        );
    }

    public function testItRefusesReferralsWhenNoneCanBeUsed(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The LDAP result holds no usable referral URI.');

        $this->subject->decode(
            Asn1::sequence(
                Asn1::enumerated(0),
                Asn1::octetString('dc=foo,dc=bar'),
                Asn1::octetString('foo'),
                self::referralsField('bar'),
            ),
            $this->context,
        );
    }

    public function testItRefusesReferralsThatWereAlreadyDecoded(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The ASN1 structure for the referrals is malformed.');

        $this->subject->decode(
            Asn1::sequence(
                Asn1::enumerated(0),
                Asn1::octetString('dc=foo,dc=bar'),
                Asn1::octetString('foo'),
                Asn1::context(
                    3,
                    Asn1::sequence(Asn1::octetString('ldap://foo')),
                ),
            ),
            $this->context,
        );
    }

    public function testItRefusesAReferralThatIsNotAnOctetString(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The ASN1 structure for a referral is malformed.');

        $this->subject->decode(
            Asn1::sequence(
                Asn1::enumerated(0),
                Asn1::octetString('dc=foo,dc=bar'),
                Asn1::octetString('foo'),
                Asn1::context(
                    3,
                    (new IncompleteType((new LdapEncoder())->encode(Asn1::integer(1))))->setIsConstructed(true),
                ),
            ),
            $this->context,
        );
    }

    public function testItRefusesAResultCodeWiderThanAnInteger(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The LDAP result code is malformed.');

        $this->subject->decode(
            Asn1::sequence(
                new EnumeratedType('18446744073709551616'),
                Asn1::octetString(''),
                Asn1::octetString(''),
            ),
            $this->context,
        );
    }

    /**
     * @param AbstractType<mixed> $type
     */
    #[DataProvider('malformedResults')]
    public function testItRefusesAMalformedResult(AbstractType $type): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The LDAP result is malformed.');

        $this->subject->decode(
            $type,
            $this->context,
        );
    }

    /**
     * @return iterable<string, array{AbstractType<mixed>}>
     */
    public static function malformedResults(): iterable
    {
        yield 'not a sequence' => [Asn1::octetString('foo')];
        yield 'a result code that is not enumerated' => [Asn1::sequence(
            Asn1::octetString('0'),
            Asn1::octetString(''),
            Asn1::octetString(''),
        )];
        yield 'a DN that is not an octet string' => [Asn1::sequence(
            Asn1::enumerated(0),
            Asn1::integer(1),
            Asn1::octetString(''),
        )];
        yield 'no diagnostic message' => [Asn1::sequence(
            Asn1::enumerated(0),
            Asn1::octetString(''),
        )];
    }
}
