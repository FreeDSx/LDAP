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
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use PHPUnit\Framework\TestCase;

final class ModifyDnRequestTest extends TestCase
{
    private ModifyDnRequest $subject;

    protected function setUp(): void
    {
        $this->subject = new ModifyDnRequest(
            dn: 'cn=foo,dc=foo,dc=bar',
            newRdn: 'cn=bar',
            deleteOldRdn: true,
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

    public function test_it_should_set_the_new_rdn(): void
    {
        self::assertEquals(
            Rdn::create('cn=bar'),
            $this->subject->getNewRdn(),
        );

        $this->subject->setNewRdn(Rdn::create('cn=foo'));

        self::assertEquals(
            Rdn::create('cn=foo'),
            $this->subject->getNewRdn(),
        );
    }

    public function test_it_should_set_whether_to_delete_the_old_rdn(): void
    {
        self::assertTrue($this->subject->getDeleteOldRdn());
        ;

        $this->subject->setDeleteOldRdn(false);

        self::assertFalse($this->subject->getDeleteOldRdn());
    }

    public function test_it_should_set_the_new_parent_dn(): void
    {
        self::assertNull($this->subject->getNewParentDn());

        $this->subject->setNewParentDn(new Dn('foo'));

        self::assertEquals(
            new Dn('foo'),
            $this->subject->getNewParentDn(),
        );
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        self::assertEquals(
            Asn1::application(12, Asn1::sequence(
                Asn1::octetString('cn=foo,dc=foo,dc=bar'),
                Asn1::octetString('cn=bar'),
                Asn1::boolean(true),
            )),
            $this->subject->toAsn1(),
        );

        $this->subject->setNewParentDn('dc=foobar');

        self::assertEquals(
            Asn1::application(12, Asn1::sequence(
                Asn1::octetString('cn=foo,dc=foo,dc=bar'),
                Asn1::octetString('cn=bar'),
                Asn1::boolean(true),
                Asn1::context(0, Asn1::octetString('dc=foobar')),
            )),
            $this->subject->toAsn1(),
        );
    }
}
