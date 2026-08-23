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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeRecorder;
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

    private InMemoryStorage $storage;

    private WriteContext $context;

    protected function setUp(): void
    {
        $this->journal = new InMemoryChangeJournal();
        $this->storage = new InMemoryStorage(
            [],
            $this->journal,
        );
        $this->subject = new ChangeRecorder($this->storage);
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

    public function test_record_modrdn_journals_the_previous_dn(): void
    {
        $this->subject->recordModRdn(
            $this->entry('cn=new,dc=example,dc=com'),
            new Dn('cn=old,dc=example,dc=com'),
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

    public function test_record_delete_captures_an_independent_pre_image(): void
    {
        $entry = $this->entry('cn=a,dc=example,dc=com');

        $this->subject->recordDelete(
            $entry,
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

    public function test_it_skips_and_warns_when_the_entry_has_no_uuid(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning');
        $recorder = new ChangeRecorder(
            $this->storage,
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

    public function test_it_is_a_no_op_for_non_journaling_storage(): void
    {
        $recorder = new ChangeRecorder($this->createMock(EntryStorageInterface::class));

        $recorder->recordAdd(
            $this->entry('cn=a,dc=example,dc=com'),
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
