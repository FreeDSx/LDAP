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
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

final class ExtendedResponseTest extends TestCase
{
    private ExtendedResponse $subject;

    protected function setUp(): void
    {
        $this->subject = new ExtendedResponse(
            new LdapResult(
                0,
                'dc=foo,dc=bar',
                'foo'
            ),
            'foo',
            'bar'
        );
    }

    public function test_it_should_get_the_name(): void
    {
        self::assertSame(
            'foo',
            $this->subject->getName(),
        );
    }

    public function test_it_should_get_the_value(): void
    {
        self::assertSame(
            'bar',
            $this->subject->getValue(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $encoder = new LdapEncoder();

        $this->subject = ExtendedResponse::fromAsn1(Asn1::application(24, Asn1::sequence(
            Asn1::enumerated(0),
            Asn1::octetString('dc=foo,dc=bar'),
            Asn1::octetString('foo'),
            Asn1::context(3, (new IncompleteType(
                $encoder->encode(Asn1::octetString('ldap://foo'))
                . $encoder->encode(Asn1::octetString('ldap://bar'))
            )))->setIsConstructed(true),
            Asn1::context(10, Asn1::octetString('foo')),
            Asn1::context(11, Asn1::octetString('bar'))
        )));

        self::assertSame(
            'foo',
            $this->subject->getName(),
        );
        self::assertSame(
            'bar',
            $this->subject->getValue(),
        );
    }
}
