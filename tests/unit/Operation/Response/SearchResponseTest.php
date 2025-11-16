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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\Response\SearchResultReference;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Result\EntryResult;
use FreeDSx\Ldap\Search\Result\ReferralResult;
use PHPUnit\Framework\TestCase;

final class SearchResponseTest extends TestCase
{
    private SearchResponse $subject;

    protected function setUp(): void
    {
        $this->subject = new SearchResponse(
            new LdapResult(
                0,
                'dc=foo,dc=bar',
                'foo',
                new LdapUrl('foo')
            ),
            [
                new EntryResult(new LdapMessageResponse(
                    1,
                    new SearchResultEntry(Entry::create('foo'))
                )),
                new EntryResult(new LdapMessageResponse(
                    1,
                    new SearchResultEntry(Entry::create('bar'))
                )),
            ],
            [
                new ReferralResult(new LdapMessageResponse(
                    1,
                    new SearchResultReference(new LdapUrl('ldap://foo'))
                )),
            ]
        );
    }

    public function test_it_should_get_the_ldap_result_values(): void
    {
        self::assertSame(
            0,
            $this->subject->getResultCode(),
        );
        self::assertEquals(
            new Dn('dc=foo,dc=bar'),
            $this->subject->getDn(),
        );
        self::assertSame(
            'foo',
            $this->subject->getDiagnosticMessage(),
        );
        self::assertEquals(
            [new LdapUrl('foo')],
            $this->subject->getReferrals(),
        );
    }

    public function test_it_should_get_the_entries(): void
    {
        self::assertEquals(
            new Entries(
                Entry::create('foo'),
                Entry::create('bar')
            ),
            $this->subject->getEntries(),
        );
    }

    public function test_it_should_get_the_referral_results(): void
    {
        self::assertEquals(
            [
                new ReferralResult(new LdapMessageResponse(
                    1,
                    new SearchResultReference(new LdapUrl('ldap://foo'))
                )),
            ],
            $this->subject->getReferralResults(),
        );
    }

    public function test_it_should_get_the_entry_results(): void
    {
        self::assertEquals(
            [
                new EntryResult(new LdapMessageResponse(
                    1,
                    new SearchResultEntry(Entry::create('foo'))
                )),
                new EntryResult(new LdapMessageResponse(
                    1,
                    new SearchResultEntry(Entry::create('bar'))
                )),
            ],
            $this->subject->getEntryResults(),
        );
    }
}
