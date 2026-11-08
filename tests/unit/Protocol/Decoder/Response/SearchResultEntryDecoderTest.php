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
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use FreeDSx\Ldap\Protocol\Decoder\Response\SearchResultEntryDecoder;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class SearchResultEntryDecoderTest extends TestCase
{
    use ServerContainerTrait;

    private SearchResultEntryDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(SearchResultEntryDecoder::class);
        $this->context = $this->fromContainer(DecodeContextFactory::class)->create();
    }

    public function testItDecodesTheEntry(): void
    {
        self::assertEquals(
            Entry::create(
                'dc=foo,dc=bar',
                ['cn' => ['foo'], 'sn' => ['foo', 'bar']],
            ),
            $this->subject->decode(
                Asn1::application(
                    4,
                    Asn1::sequence(
                        Asn1::octetString('dc=foo,dc=bar'),
                        Asn1::sequenceOf(
                            Asn1::sequence(
                                Asn1::octetString('cn'),
                                Asn1::sequenceOf(Asn1::octetString('foo')),
                            ),
                            Asn1::sequence(
                                Asn1::octetString('sn'),
                                Asn1::sequenceOf(
                                    Asn1::octetString('foo'),
                                    Asn1::octetString('bar'),
                                ),
                            ),
                        ),
                    ),
                ),
                $this->context,
            )->getEntry(),
        );
    }

    public function testItDecodesValuesSentAsASet(): void
    {
        self::assertEquals(
            Entry::create(
                'dc=foo,dc=bar',
                ['sn' => ['foo', 'bar']],
            ),
            $this->subject->decode(
                Asn1::application(
                    4,
                    Asn1::sequence(
                        Asn1::octetString('dc=foo,dc=bar'),
                        Asn1::sequenceOf(Asn1::sequence(
                            Asn1::octetString('sn'),
                            Asn1::setOf(
                                Asn1::octetString('foo'),
                                Asn1::octetString('bar'),
                            ),
                        )),
                    ),
                ),
                $this->context,
            )->getEntry(),
        );
    }

    public function testItDecodesAnEntryWithNoAttributes(): void
    {
        self::assertEquals(
            Entry::create('dc=foo,dc=bar'),
            $this->subject->decode(
                Asn1::sequence(Asn1::octetString('dc=foo,dc=bar')),
                $this->context,
            )->getEntry(),
        );
    }

    /**
     * @param AbstractType<mixed> $type
     */
    #[DataProvider('malformedEntries')]
    public function testItRefusesAMalformedEntry(AbstractType $type): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The search result entry is malformed.');

        $this->subject->decode(
            $type,
            $this->context,
        );
    }

    /**
     * @return iterable<string, array{AbstractType<mixed>}>
     */
    public static function malformedEntries(): iterable
    {
        yield 'a DN that is not an octet string' => [Asn1::sequence(
            Asn1::integer(1),
            Asn1::sequenceOf(),
        )];
        yield 'an attribute name that is not an octet string' => [Asn1::sequence(
            Asn1::octetString('dc=foo,dc=bar'),
            Asn1::sequenceOf(Asn1::sequence(
                Asn1::integer(1),
                Asn1::setOf(Asn1::octetString('foo')),
            )),
        )];
        yield 'a value that is not an octet string' => [Asn1::sequence(
            Asn1::octetString('dc=foo,dc=bar'),
            Asn1::sequenceOf(Asn1::sequence(
                Asn1::octetString('cn'),
                Asn1::setOf(Asn1::integer(1)),
            )),
        )];
    }
}
