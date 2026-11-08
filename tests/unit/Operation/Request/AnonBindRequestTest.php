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
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use PHPUnit\Framework\TestCase;

final class AnonBindRequestTest extends TestCase
{
    private AnonBindRequest $subject;

    protected function setUp(): void
    {
        $this->subject = new AnonBindRequest();
    }

    public function test_it_should_default_to_ldap_v3(): void
    {
        self::assertSame(
            3,
            $this->subject->getVersion(),
        );
    }

    public function test_it_should_have_an_empty_username_by_default(): void
    {
        self::assertSame(
            '',
            $this->subject->getUsername(),
        );
    }

    public function test_it_should_set_the_username(): void
    {
        $this->subject->setUsername('foo');

        self::assertSame(
            'foo',
            $this->subject->getUsername(),
        );
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        self::assertEquals(
            Asn1::application(0, Asn1::sequence(
                Asn1::integer(3),
                Asn1::octetString(''),
                Asn1::context(0, Asn1::octetString('')),
            )),
            $this->subject->toAsn1(),
        );
    }
}
