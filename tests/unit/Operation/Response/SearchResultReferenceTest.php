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
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\Response\SearchResultReference;
use PHPUnit\Framework\TestCase;

final class SearchResultReferenceTest extends TestCase
{
    private SearchResultReference $subject;

    protected function setUp(): void
    {
        $this->subject = new SearchResultReference(
            new LdapUrl('foo'),
            new LdapUrl('bar'),
        );
    }

    public function test_it_should_get_the_referrals(): void
    {
        self::assertEquals(
            [
                new LdapUrl('foo'),
                new LdapUrl('bar'),
            ],
            $this->subject->getReferrals(),
        );
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        self::assertEquals(
            Asn1::application(19, Asn1::sequence(
                Asn1::octetString('ldap://foo/'),
                Asn1::octetString('ldap://bar/'),
            )),
            $this->subject->toAsn1(),
        );
    }
}
