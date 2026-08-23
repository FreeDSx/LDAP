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

namespace Tests\Unit\FreeDSx\Ldap\Sync\Provider;

use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncIdSet;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Server\Utility\Uuid;
use FreeDSx\Ldap\Sync\Provider\SyncResult;
use FreeDSx\Ldap\Sync\Provider\SyncResultBatcher;
use PHPUnit\Framework\TestCase;

final class SyncResultBatcherTest extends TestCase
{
    private const MESSAGE_ID = 7;

    private SyncResultBatcher $subject;

    protected function setUp(): void
    {
        $this->subject = new SyncResultBatcher();
    }

    public function test_a_single_delete_stays_an_entry(): void
    {
        $responses = $this->batch([$this->delete('cn=alice,dc=example,dc=com')]);

        self::assertCount(
            1,
            $responses,
        );
        self::assertInstanceOf(
            SearchResultEntry::class,
            $responses[0]->getResponse(),
        );
    }

    public function test_multiple_deletes_coalesce_into_one_id_set(): void
    {
        $responses = $this->batch([
            $this->delete('cn=alice,dc=example,dc=com'),
            $this->delete('cn=bob,dc=example,dc=com'),
            $this->delete('cn=carol,dc=example,dc=com'),
        ]);

        self::assertCount(
            1,
            $responses,
        );

        $idSet = $responses[0]->getResponse();
        self::assertInstanceOf(
            SyncIdSet::class,
            $idSet,
        );
        self::assertTrue($idSet->getRefreshDeletes());
        self::assertCount(
            3,
            $idSet->getEntryUuids(),
        );
    }

    public function test_the_coalesced_set_carries_the_binary_uuid_of_each_delete(): void
    {
        $uuid = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
        $responses = $this->batch([
            $this->delete('cn=alice,dc=example,dc=com', $uuid),
            $this->delete('cn=bob,dc=example,dc=com'),
        ]);

        $idSet = $responses[0]->getResponse();
        self::assertInstanceOf(
            SyncIdSet::class,
            $idSet,
        );
        self::assertSame(
            Uuid::toBinary($uuid),
            $idSet->getEntryUuids()[0],
        );
    }

    public function test_adds_pass_through_in_order_around_a_delete_set(): void
    {
        $responses = $this->batch([
            $this->add('cn=alice,dc=example,dc=com'),
            $this->delete('cn=bob,dc=example,dc=com'),
            $this->delete('cn=carol,dc=example,dc=com'),
        ]);

        self::assertCount(
            2,
            $responses,
        );
        self::assertInstanceOf(
            SearchResultEntry::class,
            $responses[0]->getResponse(),
        );
        self::assertInstanceOf(
            SyncIdSet::class,
            $responses[1]->getResponse(),
        );
    }

    public function test_an_add_between_deletes_does_not_flush_the_pending_set(): void
    {
        $responses = $this->batch([
            $this->delete('cn=alice,dc=example,dc=com'),
            $this->add('cn=bob,dc=example,dc=com'),
            $this->delete('cn=carol,dc=example,dc=com'),
        ]);

        self::assertCount(
            2,
            $responses,
        );
        self::assertInstanceOf(
            SearchResultEntry::class,
            $responses[0]->getResponse(),
        );

        $idSet = $responses[1]->getResponse();
        self::assertInstanceOf(
            SyncIdSet::class,
            $idSet,
        );
        self::assertCount(
            2,
            $idSet->getEntryUuids(),
        );
    }

    public function test_deletes_beyond_the_cap_split_across_sets(): void
    {
        $this->subject = new SyncResultBatcher(maxSetSize: 2);

        $responses = $this->batch([
            $this->delete('cn=alice,dc=example,dc=com'),
            $this->delete('cn=bob,dc=example,dc=com'),
            $this->delete('cn=carol,dc=example,dc=com'),
            $this->delete('cn=dave,dc=example,dc=com'),
        ]);

        self::assertCount(
            2,
            $responses,
        );

        foreach ($responses as $response) {
            $idSet = $response->getResponse();
            self::assertInstanceOf(
                SyncIdSet::class,
                $idSet,
            );
            self::assertCount(
                2,
                $idSet->getEntryUuids(),
            );
        }
    }

    public function test_a_lone_delete_trailing_a_full_set_stays_an_entry(): void
    {
        $this->subject = new SyncResultBatcher(maxSetSize: 2);

        $responses = $this->batch([
            $this->delete('cn=alice,dc=example,dc=com'),
            $this->delete('cn=bob,dc=example,dc=com'),
            $this->delete('cn=carol,dc=example,dc=com'),
        ]);

        self::assertCount(
            2,
            $responses,
        );
        self::assertInstanceOf(
            SyncIdSet::class,
            $responses[0]->getResponse(),
        );
        self::assertInstanceOf(
            SearchResultEntry::class,
            $responses[1]->getResponse(),
        );
    }

    public function test_nothing_is_emitted_for_an_empty_stream(): void
    {
        self::assertSame(
            [],
            $this->batch([]),
        );
    }

    /**
     * @param list<SyncResult> $results
     * @return list<LdapMessageResponse>
     */
    private function batch(array $results): array
    {
        return iterator_to_array(
            $this->subject->batch(
                $results,
                self::MESSAGE_ID,
            ),
            false,
        );
    }

    private function delete(
        string $dn,
        string $uuid = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    ): SyncResult {
        return new SyncResult(
            new SearchResultEntry(new Entry($dn)),
            new SyncStateControl(
                SyncStateControl::STATE_DELETE,
                Uuid::toBinary($uuid),
            ),
        );
    }

    private function add(
        string $dn,
        string $uuid = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
    ): SyncResult {
        return new SyncResult(
            new SearchResultEntry(new Entry($dn)),
            new SyncStateControl(
                SyncStateControl::STATE_ADD,
                Uuid::toBinary($uuid),
            ),
        );
    }
}
