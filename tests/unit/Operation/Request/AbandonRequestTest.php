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
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use PHPUnit\Framework\TestCase;

final class AbandonRequestTest extends TestCase
{
    private AbandonRequest $subject;

    protected function setUp(): void
    {
        parent::setUp();
        $this->subject = new AbandonRequest(1);
    }

    public function testItShouldGetTheMessageId(): void
    {
        $this->assertEquals(1, $this->subject->getMessageId());
        $this->assertEquals(2, $this->subject->setMessageId(2)->getMessageId());
    }

    public function testItShouldGenerateCorrectAsn1(): void
    {
        $expected = Asn1::application(16, Asn1::integer(1));
        $this->assertEquals($expected, $this->subject->toAsn1());
    }

    public function testItShouldBeConstructedFromAsn1(): void
    {
        $result = AbandonRequest::fromAsn1(Asn1::application(16, Asn1::integer(1)));
        $expected = new AbandonRequest(1);
        $this->assertEquals($expected, $result);
    }

    public function testItShouldNotAllowNonIntegersFromAsn1(): void
    {
        $this->expectException(ProtocolException::class);
        
        AbandonRequest::fromAsn1(
            Asn1::application(
                16,
                Asn1::octetString('foo')
            )
        );
    }
}
