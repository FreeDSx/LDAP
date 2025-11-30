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

namespace Tests\Unit\FreeDSx\Ldap\Search\Result;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\UnexpectedValueException;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\Response\SearchResultReference;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Result\ReferralResult;
use PHPUnit\Framework\TestCase;

final class ReferralResultTest extends TestCase
{
    private ReferralResult $subject;

    protected function setUp(): void
    {
        $this->subject = new ReferralResult(
            new LdapMessageResponse(
                1,
                new SearchResultReference(
                    new LdapUrl('foo'),
                ),
            )
        );
    }

    public function test_it_should_get_the_referrals(): void
    {
        self::assertEquals(
            [new LdapUrl('foo')],
            $this->subject->getReferrals(),
        );
    }

    public function test_it_should_get_the_number_of_referrals(): void
    {
        self::assertCount(
            1,
            $this->subject,
        );
    }

    public function test_it_should_iterate_the_referrals(): void
    {
        self::assertEquals(
            new \ArrayIterator([
                new LdapUrl('foo')
            ]),
            $this->subject->getIterator(),
        );
    }

    public function test_it_should_have_a_string_representation_of_the_string_referral(): void
    {
        self::assertSame(
            'ldap://foo/',
            (string) $this->subject,
        );
    }

    public function test_it_must_have_a_SearchReferenceResponse(): void
    {
        self::expectException(UnexpectedValueException::class);
        self::expectExceptionMessage(sprintf(
            'Expected an instance of "%s", but got "%s".',
            SearchResultReference::class,
            SearchResultEntry::class,
        ));

        $this->subject = new ReferralResult(
            new LdapMessageResponse(
                1,
                new SearchResultEntry(
                    new Entry('cn=foo')
                ),
            )
        );

        $this->subject->getReferrals();
    }
}
