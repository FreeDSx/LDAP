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

namespace Tests\Unit\FreeDSx\Ldap\Operation\Response;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use PHPUnit\Framework\TestCase;

final class SearchResultEntryTest extends TestCase
{
    private SearchResultEntry $subject;

    protected function setUp(): void
    {
        $this->subject = new SearchResultEntry(Entry::create(
            'cn=foo,dc=foo,dc=bar',
            ['cn' => 'foo']
        ));
    }

    public function test_it_should_get_the_entry(): void
    {
        self::assertEquals(
            Entry::create('cn=foo,dc=foo,dc=bar', ['cn' => 'foo']),
            $this->subject->getEntry(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $this->subject = SearchResultEntry::fromAsn1(Asn1::application(4, Asn1::sequence(
            Asn1::octetString('dc=foo,dc=bar'),
            Asn1::sequenceOf(
                Asn1::sequence(
                    Asn1::octetString('cn'),
                    Asn1::sequenceOf(
                        Asn1::octetString('foo')
                    )
                ),
                Asn1::sequence(
                    Asn1::octetString('sn'),
                    Asn1::sequenceOf(
                        Asn1::octetString('foo'),
                        Asn1::octetString('bar')
                    )
                ),
            ),
        )));

        self::assertEquals(
            Entry::create('dc=foo,dc=bar', ['cn' => ['foo'], 'sn' => ['foo', 'bar']]),
            $this->subject->getEntry(),
        );
    }

    public function test_it_should_be_constructed_from_asn1_with_set_of_vals(): void
    {
        $this->subject = SearchResultEntry::fromAsn1(Asn1::application(4, Asn1::sequence(
            Asn1::octetString('dc=foo,dc=bar'),
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
                ),
            ),
        )));

        self::assertEquals(
            Entry::create('dc=foo,dc=bar', ['cn' => ['foo'], 'sn' => ['foo', 'bar']]),
            $this->subject->getEntry(),
        );
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        self::assertEquals(
            Asn1::application(4, Asn1::sequence(
                Asn1::octetString('cn=foo,dc=foo,dc=bar'),
                Asn1::sequenceOf(
                    Asn1::sequence(
                        Asn1::octetString('cn'),
                        Asn1::setOf(
                            Asn1::octetString('foo')
                        ),
                    ),
                ),
            )),
            $this->subject->toAsn1(),
        );
    }
}
