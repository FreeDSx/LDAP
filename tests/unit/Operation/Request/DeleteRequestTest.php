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
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use PHPUnit\Framework\TestCase;

final class DeleteRequestTest extends TestCase
{
    private DeleteRequest $subject;

    protected function setUp(): void
    {
        $this->subject = new DeleteRequest('cn=foo,dc=foo,dc=bar');
    }

    public function test_it_should_set_the_dn(): void
    {
        self::assertEquals(
            new Dn('cn=foo,dc=foo,dc=bar'),
            $this->subject->getDn(),
        );

        $this->subject->setDn(new Dn('foo'));

        self::assertEquals(
            new Dn('foo'),
            $this->subject->getDn(),
        );
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        self::assertEquals(
            Asn1::application(10, Asn1::octetString('cn=foo,dc=foo,dc=bar')),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $this->subject = DeleteRequest::fromAsn1(Asn1::application(10, Asn1::octetString(
            'dc=foo,dc=bar'
        )));

        self::assertEquals(
            new Dn('dc=foo,dc=bar'),
            $this->subject->getDn(),
        );
    }

    /**
     * @dataProvider malformedAsn1DataProvider
     */
    public function test_it_should_not_be_constructed_from_invalid_asn1(AbstractType $type): void
    {
        $this->expectException(ProtocolException::class);

        DeleteRequest::fromAsn1($type);
    }

    /**
     * @return array<array<AbstractType>>
     */
    public static function malformedAsn1DataProvider(): array
    {
        return [
            [Asn1::application(11, Asn1::octetString(
                'dc=foo,dc=bar'
            ))],
            [Asn1::application(11, Asn1::integer(
                2
            ))],
        ];
    }
}
