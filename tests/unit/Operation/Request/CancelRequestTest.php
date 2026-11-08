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
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

final class CancelRequestTest extends TestCase
{
    private CancelRequest $subject;

    protected function setUp(): void
    {
        $this->subject = new CancelRequest(1);
    }

    public function test_it_should_set_the_message_id(): void
    {
        self::assertSame(
            1,
            $this->subject->getMessageId(),
        );

        $this->subject->setMessageId(2);

        self::assertSame(
            2,
            $this->subject->getMessageId(),
        );
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            Asn1::application(23, Asn1::sequence(
                Asn1::context(0, Asn1::octetString(ExtendedRequest::OID_CANCEL)),
                Asn1::context(1, Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::integer(1),
                )))),
            )),
            $this->subject->toAsn1(),
        );
    }
}
