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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Journal\Audit;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Audit\AuditingChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\InMemoryChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\RetentionPolicy;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Tests\Support\FreeDSx\Ldap\Journal\Audit\CapturingAuditSink;
use Tests\Support\FreeDSx\Ldap\Journal\Audit\FailingAuditSink;

final class AuditingChangeJournalTest extends TestCase
{
    public function test_wrap_decorates_the_journal_when_the_config_carries_a_sink(): void
    {
        $wrapped = AuditingChangeJournal::wrap(
            new InMemoryChangeJournal(),
            new ChangeJournalConfig(auditSink: new CapturingAuditSink()),
        );

        self::assertInstanceOf(
            AuditingChangeJournal::class,
            $wrapped,
        );
    }

    public function test_wrap_returns_the_journal_untouched_without_a_sink(): void
    {
        $journal = new InMemoryChangeJournal();

        self::assertSame(
            $journal,
            AuditingChangeJournal::wrap(
                $journal,
                new ChangeJournalConfig(),
            ),
        );
    }

    public function test_it_tees_each_appended_record_to_the_sink(): void
    {
        $sink = new CapturingAuditSink();
        $journal = new AuditingChangeJournal(
            new InMemoryChangeJournal(),
            $sink,
        );

        $record = $journal->append($this->change('cn=a,dc=example,dc=com'));

        self::assertCount(
            1,
            $sink->written,
        );
        self::assertSame(
            $record,
            $sink->written[0],
        );
    }

    public function test_a_sink_failure_is_logged_and_the_record_is_still_journaled(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('error');
        $journal = new AuditingChangeJournal(
            new InMemoryChangeJournal(),
            new FailingAuditSink(),
            $logger,
        );

        $record = $journal->append($this->change('cn=a,dc=example,dc=com'));

        self::assertSame(
            1,
            $record->seq,
        );
        self::assertCount(
            1,
            iterator_to_array($journal->read()),
        );
    }

    public function test_read_latest_seq_and_prune_delegate_to_the_inner_journal(): void
    {
        $journal = new AuditingChangeJournal(
            new InMemoryChangeJournal(),
            new CapturingAuditSink(),
        );
        $journal->append($this->change('cn=a,dc=example,dc=com'));
        $journal->append($this->change('cn=b,dc=example,dc=com'));

        self::assertSame(
            2,
            $journal->latestSeq(),
        );
        self::assertCount(
            1,
            iterator_to_array($journal->read(1)),
        );

        $journal->prune(new RetentionPolicy(maxRecords: 1));

        self::assertCount(
            1,
            iterator_to_array($journal->read()),
        );
    }

    private function change(string $dn): PendingChange
    {
        return new PendingChange(
            changeType: ChangeType::Add,
            dn: new Dn($dn),
            entryUuid: '11111111-1111-4111-8111-111111111111',
            authzId: AuthzId::anonymous(),
        );
    }
}
