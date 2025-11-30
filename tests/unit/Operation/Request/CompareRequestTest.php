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

namespace Tests\Unit\FreeDSx\Ldap\Operation\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use PHPUnit\Framework\TestCase;

final class CompareRequestTest extends TestCase
{
    private CompareRequest $subject;

    protected function setUp(): void
    {
        $this->subject = new CompareRequest(
            'dc=foo,dc=bar',
            new EqualityFilter('foo', 'bar')
        );
    }

    public function test_it_should_set_the_dn(): void
    {
        self::assertEquals(
            'dc=foo,dc=bar',
            $this->subject->getDn(),
        );

        $this->subject->setDn('dc=foobar');

        self::assertEquals(
            new Dn('dc=foobar'),
            $this->subject->getDn(),
        );
    }

    public function test_it_should_set_the_filter(): void
    {
        self::assertEquals(
            new EqualityFilter('foo', 'bar'),
            $this->subject->getFilter(),
        );

        $this->subject->setFilter(new EqualityFilter('cn', 'foo'));

        self::assertEquals(
            new EqualityFilter('cn', 'foo'),
            $this->subject->getFilter(),
        );
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        self::assertEquals(
            Asn1::application(14, Asn1::sequence(
                Asn1::octetString('dc=foo,dc=bar'),
                Asn1::universal(AbstractType::TAG_TYPE_SEQUENCE, (new EqualityFilter('foo', 'bar'))->toAsn1())
            )),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $req = new CompareRequest('foo', new EqualityFilter('foo', 'bar'));

        self::assertEquals(
            $req,
            CompareRequest::fromAsn1($req->toAsn1()),
        );
    }

    /**
     * @dataProvider malformedAsn1DataProvider
     */
    public function test_it_should_detect_invalid_asn1_from_asn1(AbstractType $type): void
    {
        $this->expectException(ProtocolException::class);

        CompareRequest::fromAsn1(Asn1::octetString('foo'));
    }

    /**
     * @return array<array<AbstractType>>
     */
    public static function malformedAsn1DataProvider(): array
    {
        return [
            [Asn1::octetString('foo')],
            [Asn1::sequence()],
            [Asn1::sequence(Asn1::octetString('foo'))],
            [Asn1::sequence(Asn1::octetString('foo'), Asn1::sequence())],
        ];
    }
}
