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
use FreeDSx\Ldap\Entry\Dn;
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
}
