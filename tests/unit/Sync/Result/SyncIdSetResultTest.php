<?php

declare(strict_types=1);

namespace Tests\Unit\FreeDSx\Ldap\Sync\Result;

use FreeDSx\Ldap\Exception\UnexpectedValueException;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\Response\SearchResultReference;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncIdSet;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;
use PHPUnit\Framework\TestCase;

final class SyncIdSetResultTest extends TestCase
{
    private SyncIdSetResult $subject;

    protected function setUp(): void
    {
        $this->subject = new SyncIdSetResult(
            new LdapMessageResponse(
                1,
                new SyncIdSet(
                    ['foo', 'bar'],
                    true,
                    'tasty',
                ),
            ),
        );
    }

    public function test_it_should_get_the_entry_uuids(): void
    {
        self::assertSame(
            [
                'foo',
                'bar',
            ],
            $this->subject->getEntryUuids(),
        );
    }

    public function test_it_should_decode_the_entry_uuids_from_their_wire_form(): void
    {
        $subject = new SyncIdSetResult(
            new LdapMessageResponse(
                1,
                new SyncIdSet([
                    pack('H*', '0f8fad5bd9cb469fa16570867728950e'),
                    pack('H*', '7d4448409dc011d1b2455ffdce74fad2'),
                ]),
            ),
        );

        self::assertSame(
            [
                '0f8fad5b-d9cb-469f-a165-70867728950e',
                '7d444840-9dc0-11d1-b245-5ffdce74fad2',
            ],
            $subject->getDecodedEntryUuids(),
        );
    }

    public function test_it_should_get_the_count_of_the_set(): void
    {
        self::assertCount(
            2,
            $this->subject,
        );
    }

    public function test_it_should_get_the_iterable_set(): void
    {
        self::assertEquals(
            new \ArrayIterator([
                'foo',
                'bar',
            ]),
            $this->subject->getIterator(),
        );
    }

    public function test_it_should_get_the_raw_message(): void
    {
        self::assertEquals(
            new LdapMessageResponse(
                1,
                new SyncIdSet(
                    ['foo', 'bar'],
                    true,
                    'tasty',
                ),
            ),
            $this->subject->getMessage(),
        );
    }

    public function test_it_should_get_the_cookie(): void
    {
        self::assertSame(
            'tasty',
            $this->subject->getCookie(),
        );
    }

    public function test_it_should_get_if_this_is_for_entry_deletes(): void
    {
        $this->subject = new SyncIdSetResult(
            new LdapMessageResponse(
                1,
                new SyncIdSet(
                    ['foo', 'bar'],
                    true,
                    'tasty',
                ),
            ),
        );

        self::assertTrue($this->subject->isDeleted());
        self::assertFalse($this->subject->isPresent());
    }

    public function test_it_should_get_if_this_is_for_entry_that_are_present(): void
    {
        $this->subject = new SyncIdSetResult(
            new LdapMessageResponse(
                1,
                new SyncIdSet(
                    ['foo', 'bar'],
                    false,
                    'tasty',
                ),
            ),
        );

        self::assertTrue($this->subject->isPresent());
        self::assertFalse($this->subject->isDeleted());
    }

    public function test_it_must_have_a_SearchEntryResponse(): void
    {
        $this->subject = new SyncIdSetResult(
            new LdapMessageResponse(
                1,
                new SearchResultReference(
                    new LdapUrl('foo'),
                ),
            ),
        );

        self::expectException(UnexpectedValueException::class);
        self::expectExceptionMessage(sprintf(
            'Expected an instance of "%s", but got "%s".',
            SyncIdSet::class,
            SearchResultReference::class,
        ));

        $this->subject->getEntryUuids();
    }
}
