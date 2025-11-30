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
use FreeDSx\Ldap\Search\Result\EntryResult;
use PHPUnit\Framework\TestCase;

final class EntryResultTest extends TestCase
{
    private EntryResult $subject;

    protected function setUp(): void
    {
        $this->subject = new EntryResult(
            new LdapMessageResponse(
                1,
                new SearchResultEntry(
                    new Entry('cn=foo')
                ),
            )
        );
    }

    public function test_it_should_get_the_entry(): void
    {
        self::assertEquals(
            new Entry('cn=foo'),
            $this->subject->getEntry(),
        );
    }

    public function test_it_should_get_the_raw_message(): void
    {
        self::assertEquals(
            new LdapMessageResponse(
                1,
                new SearchResultEntry(
                    new Entry('cn=foo')
                ),
            ),
            $this->subject->getMessage(),
        );
    }

    public function test_it_should_have_a_string_representation_if_the_dn_of_the_entry(): void
    {
        self::assertSame(
            'cn=foo',
            (string) $this->subject,
        );
    }

    public function test_it_must_have_a_SearchEntryResponse(): void
    {
        self::expectException(UnexpectedValueException::class);
        self::expectExceptionMessage(sprintf(
            'Expected an instance of "%s", but got "%s".',
            SearchResultEntry::class,
            SearchResultReference::class,
        ));

        $this->subject = new EntryResult(
            new LdapMessageResponse(
                1,
                new SearchResultReference(
                    new LdapUrl('foo')
                ),
            )
        );
        $this->subject->getEntry();
    }
}
