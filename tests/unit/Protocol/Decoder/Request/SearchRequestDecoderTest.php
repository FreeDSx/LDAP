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
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use FreeDSx\Ldap\Protocol\Decoder\Request\SearchRequestDecoder;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\TrailingComponentTrait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class SearchRequestDecoderTest extends TestCase
{
    use ServerContainerTrait;
    use TrailingComponentTrait;

    private SearchRequestDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(SearchRequestDecoder::class);
        $this->context = $this->fromContainer(DecodeContextFactory::class)->create();
    }

    public function testItDecodesEachFieldOfTheSearch(): void
    {
        $search = (new SearchRequest(
            new EqualityFilter(
                'foo',
                'bar',
            ),
            'cn',
        ))
            ->base('dc,=foo,dc=bar')
            ->timeLimit(10)
            ->sizeLimit(5)
            ->useBaseScope()
            ->setAttributesOnly(true)
            ->setDereferenceAliases(2);

        $decoded = $this->subject->decode(
            $search->toAsn1(),
            $this->context,
        );

        self::assertEquals(
            new Dn('dc,=foo,dc=bar'),
            $decoded->getBaseDn(),
        );
        self::assertSame(
            [5, 10, SearchRequest::SCOPE_BASE_OBJECT, true, 2],
            [
                $decoded->getSizeLimit(),
                $decoded->getTimeLimit(),
                $decoded->getScope(),
                $decoded->getAttributesOnly(),
                $decoded->getDereferenceAliases(),
            ],
        );
    }

    public function testItIgnoresATrailingComponentItDoesNotRecognize(): void
    {
        $search = (new SearchRequest(
            new EqualityFilter(
                'foo',
                'bar',
            ),
            'cn',
        ))->base('dc=foo,dc=bar');

        self::assertEquals(
            $search->toAsn1(),
            $this->subject->decode(
                self::withTrailingComponent($search->toAsn1()),
                $this->context,
            )->toAsn1(),
        );
    }

    public function testItChecksTheAttributesBeforeTheNumericFields(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The search request is malformed.');

        $this->subject->decode(
            Asn1::sequence(
                Asn1::octetString('dc=foo'),
                Asn1::enumerated(2),
                Asn1::enumerated(0),
                Asn1::integer(0),
                Asn1::integer(0),
                Asn1::boolean(false),
                Asn1::context(
                    7,
                    Asn1::octetString('cn'),
                ),
                Asn1::sequenceOf(Asn1::integer(1)),
            ),
            $this->context,
        );
    }

    /**
     * @param AbstractType<mixed> $type
     */
    #[DataProvider('malformedRequests')]
    public function testItRefusesAMalformedRequest(AbstractType $type): void
    {
        $this->expectException(ProtocolException::class);

        $this->subject->decode(
            $type,
            $this->context,
        );
    }

    /**
     * @return array<string, array{AbstractType<mixed>}>
     */
    public static function malformedRequests(): array
    {
        return [
            'not a sequence' => [Asn1::set()],
            'no components' => [Asn1::sequence()],
            'too few components' => [Asn1::sequence(
                Asn1::integer(5),
                Asn1::octetString('foo'),
            )],
        ];
    }
}
