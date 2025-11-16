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

namespace Tests\Unit\FreeDSx\Ldap\Control\Sorting;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

class SortingControlTest extends TestCase
{
    private SortingControl $subject;

    protected function setUp(): void
    {
        $this->subject = new SortingControl(
            new SortKey('foo'),
            new SortKey('bar'),
        );
    }

    public function test_it_should_have_the_sorting_oid(): void
    {
        self::assertSame(
            Control::OID_SORTING,
            $this->subject->getTypeOid(),
        );
    }

    public function test_it_should_get_the_sort_keys(): void
    {
        self::assertEquals(
            [
                new SortKey('foo'),
                new SortKey('bar'),
            ],
            $this->subject->getSortKeys(),
        );
    }

    public function test_it_should_set_sort_keys(): void
    {
        $this->subject->setSortKeys(new SortKey('foobar'));

        self::assertEquals(
            [new SortKey('foobar')],
            $this->subject->getSortKeys(),
        );
    }

    public function test_it_should_add_sort_keys(): void
    {
        $key = new SortKey('foobar');
        $this->subject->addSortKeys($key);

        self::assertContains(
            $key,
            $this->subject->getSortKeys(),
        );
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        $this->subject->addSortKeys(
            new SortKey(
                'foobar',
                true,
                'bleh'
            )
        );

        $encoder = new LdapEncoder();

        self::assertEquals(
            Asn1::sequence(
                Asn1::octetString(Control::OID_SORTING),
                Asn1::boolean(false),
                Asn1::octetString($encoder->encode(Asn1::sequenceOf(
                    Asn1::sequence(Asn1::octetString('foo')),
                    Asn1::sequence(Asn1::octetString('bar')),
                    Asn1::sequence(
                        Asn1::octetString('foobar'),
                        Asn1::context(0, Asn1::octetString('bleh')),
                        Asn1::context(1, Asn1::boolean(true))
                    )
                )))
            ),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            new SortingControl(
                new SortKey('foo'),
                new SortKey('bar'),
                new SortKey('foobar', true, 'bleh')
            ),
            SortingControl::fromAsn1(Asn1::sequence(
                Asn1::octetString(Control::OID_SORTING),
                Asn1::boolean(false),
                Asn1::octetString($encoder->encode(Asn1::sequenceOf(
                    Asn1::sequence(Asn1::octetString('foo')),
                    Asn1::sequence(Asn1::octetString('bar')),
                    Asn1::sequence(
                        Asn1::octetString('foobar'),
                        Asn1::context(0, Asn1::octetString('bleh')),
                        Asn1::context(1, Asn1::boolean(true))
                    )
                )))
            ))->setValue(null)
        );
    }

    public function test_it_should_throw_an_error_parsing_sorting_keys_with_no_attribute(): void
    {
        $encoder = new LdapEncoder();

        self::expectException(ProtocolException::class);

        $this->subject->fromAsn1(Asn1::sequence(
            Asn1::octetString(Control::OID_SORTING),
            Asn1::boolean(false),
            Asn1::octetString($encoder->encode(Asn1::sequenceOf(
                Asn1::sequence(Asn1::octetString(''))
            )))
        ));
    }

    public function test_it_should_throw_an_error_parsing_sorting_keys_with_unexpected_values(): void
    {
        $encoder = new LdapEncoder();

        self::expectException(ProtocolException::class);

        $this->subject->fromAsn1(Asn1::sequence(
            Asn1::octetString(Control::OID_SORTING),
            Asn1::boolean(false),
            Asn1::octetString($encoder->encode(Asn1::sequenceOf(
                Asn1::sequence(Asn1::octetString('foo'), Asn1::enumerated(1))
            )))
        ));
    }
}
