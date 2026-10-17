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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeRecorder;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\MovedEntry;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\InMemoryChangeJournal;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

final class ChangeRecorderTest extends TestCase
{
    private ChangeRecorder $subject;

    private InMemoryChangeJournal $journal;

    private WriteContext $context;

    protected function setUp(): void
    {
        $this->journal = new InMemoryChangeJournal();
        $this->subject = new ChangeRecorder($this->journal);
        $this->context = new WriteContext(
            BindToken::fromDn('cn=admin,dc=example,dc=com'),
            new ControlBag(),
        );
    }

    public function test_record_add_journals_an_add_with_the_acting_identity(): void
    {
        $this->subject->recordAdd(
            $this->entry('cn=a,dc=example,dc=com'),
            $this->context,
        );

        $record = $this->onlyRecord();
        self::assertSame(
            ChangeType::Add,
            $record->change->changeType,
        );
        self::assertSame(
            'cn=a,dc=example,dc=com',
            $record->change->dn->toString(),
        );
        self::assertSame(
            'cn=admin,dc=example,dc=com',
            $record->change->authzId->getValue(),
        );
    }

    public function test_record_modify_journals_a_modify(): void
    {
        $this->subject->recordModify(
            $this->entry('cn=a,dc=example,dc=com'),
            $this->context,
        );

        self::assertSame(
            ChangeType::Modify,
            $this->onlyRecord()->change->changeType,
        );
    }

    public function test_record_modrdns_journals_the_previous_dn(): void
    {
        $this->subject->recordModRdns(
            [
                new MovedEntry(
                    $this->entry('cn=new,dc=example,dc=com'),
                    new Dn('cn=old,dc=example,dc=com'),
                ),
            ],
            $this->context,
        );

        $record = $this->onlyRecord();
        self::assertSame(
            ChangeType::ModRdn,
            $record->change->changeType,
        );
        self::assertSame(
            'cn=old,dc=example,dc=com',
            $record->change->previousDn?->toString(),
        );
    }

    public function test_record_modrdns_journals_each_moved_entry_in_the_order_given(): void
    {
        $this->subject->recordModRdns(
            [
                new MovedEntry(
                    $this->entry('ou=new,dc=example,dc=com'),
                    new Dn('ou=old,dc=example,dc=com'),
                ),
                new MovedEntry(
                    $this->entry('cn=a,ou=new,dc=example,dc=com'),
                    new Dn('cn=a,ou=old,dc=example,dc=com'),
                ),
            ],
            $this->context,
        );

        self::assertSame(
            [
                'ou=old,dc=example,dc=com',
                'cn=a,ou=old,dc=example,dc=com',
            ],
            array_map(
                static fn(ChangeRecord $record): ?string => $record->change->previousDn?->toString(),
                iterator_to_array(
                    $this->journal->read(),
                    false,
                ),
            ),
        );
    }

    public function test_record_deletes_captures_an_independent_pre_image(): void
    {
        $entry = $this->entry('cn=a,dc=example,dc=com');

        $this->subject->recordDeletes(
            [$entry],
            $this->context,
        );

        $preImage = $this->onlyRecord()->change->preImage;
        self::assertNotNull($preImage);
        self::assertNotSame(
            $entry,
            $preImage,
        );
        self::assertSame(
            'a',
            $preImage->get('cn')?->firstValue(),
        );
    }

    public function test_record_deletes_journals_each_entry_in_the_order_given(): void
    {
        $this->subject->recordDeletes(
            [
                $this->entry('cn=child,cn=a,dc=example,dc=com'),
                $this->entry('cn=a,dc=example,dc=com'),
            ],
            $this->context,
        );

        self::assertSame(
            [
                'cn=child,cn=a,dc=example,dc=com',
                'cn=a,dc=example,dc=com',
            ],
            array_map(
                static fn(ChangeRecord $record): string => $record->change->dn->toString(),
                iterator_to_array(
                    $this->journal->read(),
                    false,
                ),
            ),
        );
    }

    public function test_record_deletes_skips_an_entry_without_a_uuid_and_journals_the_rest(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning');
        $recorder = new ChangeRecorder(
            $this->journal,
            $logger,
        );

        $recorder->recordDeletes(
            [
                new Entry(
                    new Dn('cn=b,dc=example,dc=com'),
                    new Attribute('cn', 'b'),
                ),
                $this->entry('cn=a,dc=example,dc=com'),
            ],
            $this->context,
        );

        self::assertSame(
            'cn=a,dc=example,dc=com',
            $this->onlyRecord()->change->dn->toString(),
        );
    }

    public function test_it_skips_and_warns_when_the_entry_has_no_uuid(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning');
        $recorder = new ChangeRecorder(
            $this->journal,
            $logger,
        );

        $recorder->recordAdd(
            new Entry(
                new Dn('cn=a,dc=example,dc=com'),
                new Attribute('cn', 'a'),
            ),
            $this->context,
        );

        self::assertSame(
            0,
            $this->journal->latestSeq(),
        );
    }

    private function entry(string $dn): Entry
    {
        return new Entry(
            new Dn($dn),
            new Attribute('cn', 'a'),
            new Attribute(
                AttributeTypeOid::NAME_ENTRY_UUID,
                '11111111-1111-4111-8111-111111111111',
            ),
        );
    }

    private function onlyRecord(): ChangeRecord
    {
        $records = iterator_to_array($this->journal->read());

        self::assertCount(
            1,
            $records,
        );

        return $records[0];
    }
}
