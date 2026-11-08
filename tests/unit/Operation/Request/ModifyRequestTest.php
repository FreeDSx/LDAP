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
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use PHPUnit\Framework\TestCase;

final class ModifyRequestTest extends TestCase
{
    private ModifyRequest $subject;

    protected function setUp(): void
    {
        $this->subject = new ModifyRequest(
            'cn=foo,dc=foo,dc=bar',
            Change::replace('foo', 'bar'),
            Change::add('sn', 'bleep', 'blorp'),
        );
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

    public function test_it_should_set_the_changes(): void
    {
        self::assertEquals(
            [
                Change::replace('foo', 'bar'),
                Change::add('sn', 'bleep', 'blorp'),
            ],
            $this->subject->getChanges(),
        );

        $this->subject->setChanges(Change::delete('foo', 'bar'));

        self::assertEquals(
            [Change::delete('foo', 'bar')],
            $this->subject->getChanges(),
        );
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        self::assertEquals(
            Asn1::application(6, Asn1::sequence(
                Asn1::octetString('cn=foo,dc=foo,dc=bar'),
                Asn1::sequenceOf(
                    Asn1::sequence(
                        Asn1::enumerated(2),
                        Asn1::sequence(
                            Asn1::octetString('foo'),
                            Asn1::setOf(
                                Asn1::octetString('bar'),
                            ),
                        ),
                    ),
                    Asn1::sequence(
                        Asn1::enumerated(0),
                        Asn1::sequence(
                            Asn1::octetString('sn'),
                            Asn1::setOf(
                                Asn1::octetString('bleep'),
                                Asn1::octetString('blorp'),
                            ),
                        ),
                    ),
                ),
            )),
            $this->subject->toAsn1(),
        );
    }
}
