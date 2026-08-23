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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Journal\Read;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\InMemoryChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Read\ChangeScope;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Read\ChangeStream;
use PHPUnit\Framework\TestCase;

final class ChangeStreamTest extends TestCase
{
    private InMemoryChangeJournal $journal;

    private ChangeStream $subject;

    protected function setUp(): void
    {
        $this->journal = new InMemoryChangeJournal();
        $this->subject = new ChangeStream($this->journal);
    }

    public function test_since_returns_only_records_after_the_given_seq(): void
    {
        $this->append('cn=a,dc=example,dc=com');
        $this->append('cn=b,dc=example,dc=com');
        $this->append('cn=c,dc=example,dc=com');

        $seqs = array_map(
            static fn(ChangeRecord $record): int => $record->seq,
            iterator_to_array($this->subject->since(1)),
        );

        self::assertSame(
            [2, 3],
            $seqs,
        );
    }

    public function test_since_without_a_scope_returns_every_record(): void
    {
        $this->append('cn=a,dc=example,dc=com');
        $this->append('cn=b,dc=other,dc=com');

        self::assertCount(
            2,
            iterator_to_array($this->subject->since()),
        );
    }

    public function test_since_with_a_scope_filters_by_dn(): void
    {
        $this->append('dc=example,dc=com');
        $this->append('cn=a,dc=example,dc=com');
        $this->append('cn=b,dc=other,dc=com');

        $dns = array_map(
            static fn(ChangeRecord $record): string => $record->change->dn->toString(),
            iterator_to_array($this->subject->since(
                0,
                ChangeScope::wholeSubtree(new Dn('dc=example,dc=com')),
            )),
        );

        self::assertSame(
            ['dc=example,dc=com', 'cn=a,dc=example,dc=com'],
            $dns,
        );
    }

    public function test_latest_seq_reflects_the_journal_high_water_mark(): void
    {
        self::assertSame(
            0,
            $this->subject->latestSeq(),
        );

        $this->append('cn=a,dc=example,dc=com');
        $this->append('cn=b,dc=example,dc=com');

        self::assertSame(
            2,
            $this->subject->latestSeq(),
        );
    }

    public function test_retains_since_reflects_the_journal_window(): void
    {
        $this->append('cn=a,dc=example,dc=com');
        $this->append('cn=b,dc=example,dc=com');

        self::assertTrue($this->subject->retainsSince(0));
    }

    /**
     * A move out of scope is only visible as a delete if the record survives scope filtering to be interpreted.
     */
    public function test_since_yields_a_move_whose_previous_dn_was_in_scope(): void
    {
        $this->appendMove(
            'cn=a,dc=other,dc=com',
            'cn=a,dc=example,dc=com',
        );

        self::assertCount(
            1,
            iterator_to_array($this->subject->since(
                0,
                ChangeScope::wholeSubtree(new Dn('dc=example,dc=com')),
            )),
        );
    }

    public function test_since_skips_a_move_that_touched_the_scope_at_neither_end(): void
    {
        $this->appendMove(
            'cn=a,dc=other,dc=com',
            'cn=a,dc=elsewhere,dc=com',
        );

        self::assertCount(
            0,
            iterator_to_array($this->subject->since(
                0,
                ChangeScope::wholeSubtree(new Dn('dc=example,dc=com')),
            )),
        );
    }

    private function append(string $dn): void
    {
        $this->journal->append(new PendingChange(
            changeType: ChangeType::Add,
            dn: new Dn($dn),
            entryUuid: '11111111-1111-4111-8111-111111111111',
            authzId: AuthzId::anonymous(),
        ));
    }

    private function appendMove(
        string $dn,
        string $previousDn,
    ): void {
        $this->journal->append(new PendingChange(
            changeType: ChangeType::ModRdn,
            dn: new Dn($dn),
            entryUuid: '11111111-1111-4111-8111-111111111111',
            authzId: AuthzId::anonymous(),
            previousDn: new Dn($previousDn),
        ));
    }
}
