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
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use PHPUnit\Framework\TestCase;

final class AddRequestTest extends TestCase
{
    private AddRequest $subject;

    protected function setUp(): void
    {
        $this->subject = new AddRequest(Entry::create(
            'cn=foo,dc=foo,dc=bar',
            ['cn' => 'foo']
        ));
    }

    public function test_it_should_set_entry(): void
    {
        $entry = Entry::create('cn=foobar,dc=foo,dc=bar', ['cn' => 'foobar']);

        self::assertEquals(
            Entry::create('cn=foo,dc=foo,dc=bar', ['cn' => 'foo']),
            $this->subject->getEntry(),
        );

        $this->subject->setEntry($entry);

        self::assertEquals(
            $entry,
            $this->subject->getEntry(),
        );
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        $this->subject->setEntry(Entry::create('cn=foo,dc=foo,dc=bar', ['cn' => 'foo', 'sn' => ['foo', 'bar']]));

        self::assertEquals(
            Asn1::application(8, Asn1::sequence(
                Asn1::octetString('cn=foo,dc=foo,dc=bar'),
                Asn1::sequenceOf(
                    Asn1::sequence(
                        Asn1::octetString('cn'),
                        Asn1::setOf(
                            Asn1::octetString('foo')
                        )
                    ),
                    Asn1::sequence(
                        Asn1::octetString('sn'),
                        Asn1::setOf(
                            Asn1::octetString('foo'),
                            Asn1::octetString('bar')
                        )
                    )
                )
            )),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $add = new AddRequest(Entry::create('cn=foo,dc=foo,dc=bar', ['cn' => 'foo', 'sn' => ['foo', 'bar']]));

        self::assertEquals(
            new AddRequest(Entry::create(
                'cn=foo,dc=foo,dc=bar',
                ['cn' => 'foo', 'sn' => ['foo', 'bar']]
            )),
            AddRequest::fromAsn1($add->toAsn1())
        );
    }

    /**
     * @dataProvider malformedAsn1DataProvider
     *
     * @param AbstractType<mixed> $type
     */
    public function test_it_should_detect_a_malformed_asn1_request(AbstractType $type): void
    {
        $this->expectException(ProtocolException::class);

        $this->subject->fromAsn1($type);
    }

    /**
     * @return array<array<AbstractType<mixed>>>
     */
    public static function malformedAsn1DataProvider()
    {
        return [
            [Asn1::sequence(
                Asn1::octetString('foo'),
                Asn1::sequence(),
                Asn1::octetString('bar')
            )],
            [Asn1::sequence(
                    Asn1::octetString('foo'),
                    Asn1::sequence(),
                    Asn1::octetString('bar')
            )],
            [Asn1::sequence(
                Asn1::octetString('foo'),
                Asn1::integer(2)
            )],
            [Asn1::octetString('foo')],
            [Asn1::sequence(
                Asn1::octetString('foo'),
                Asn1::sequence(
                    Asn1::sequence(
                        Asn1::octetString('foo'),
                        Asn1::sequence()
                    )
                )
            )],
            [Asn1::sequence(
                Asn1::octetString('foo'),
                Asn1::sequence(
                    Asn1::sequence(
                        Asn1::octetString('foo')
                    )
                )
            )]
        ];
    }
}
