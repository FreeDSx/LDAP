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

namespace Tests\Unit\FreeDSx\Ldap\Protocol;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use PHPUnit\Framework\TestCase;

final class LdapMessageRequestTest extends TestCase
{
    private LdapMessageRequest $subject;

    protected function setUp(): void
    {
        $this->subject = new LdapMessageRequest(
            1,
            new DeleteRequest('dc=foo,dc=bar'),
            new Control('foo')
        );
    }

    public function test_it_should_get_the_response(): void
    {
        self::assertInstanceOf(
            DeleteRequest::class,
            $this->subject->getRequest(),
        );
    }

    public function test_it_should_get_the_controls(): void
    {
        self::assertTrue($this->subject->controls()->has('foo'));
    }

    public function test_it_should_get_the_message_id(): void
    {
        self::assertSame(
            1,
            $this->subject->getMessageId(),
        );
    }

    public function test_it_should_generate_correct_ASN1(): void
    {
        self::assertEquals(
            Asn1::sequence(
                Asn1::integer(1),
                Asn1::application(10, Asn1::octetString('dc=foo,dc=bar')),
                Asn1::context(0, Asn1::sequenceOf((new Control('foo'))->toAsn1()))
            ),
            $this->subject->toAsn1(),
        );
    }
}
