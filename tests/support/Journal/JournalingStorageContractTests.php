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

namespace Tests\Support\FreeDSx\Ldap\Journal;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeJournalingInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\InMemoryChangeJournal;

/**
 * Shared ChangeJournalingTrait contract tests.
 *
 * @mixin \PHPUnit\Framework\TestCase
 */
trait JournalingStorageContractTests
{
    public function test_an_appended_change_reaches_the_injected_journal(): void
    {
        $journal = new InMemoryChangeJournal();
        $this->makeJournalingStorage($journal)
            ->appendChange($this->journalingChange());

        self::assertCount(
            1,
            iterator_to_array($journal->read()),
        );
    }

    public function test_the_injected_journal_is_the_one_exposed(): void
    {
        $journal = new InMemoryChangeJournal();

        self::assertSame(
            $journal,
            $this->makeJournalingStorage($journal)->changeJournal(),
        );
    }

    public function test_there_is_no_journal_when_none_is_injected(): void
    {
        self::assertNull($this->makeJournalingStorage()->changeJournal());
    }

    public function test_appending_without_a_journal_does_nothing(): void
    {
        $this->expectNotToPerformAssertions();

        $this->makeJournalingStorage()
            ->appendChange($this->journalingChange());
    }

    abstract protected function makeJournalingStorage(?ChangeJournalInterface $journal = null): ChangeJournalingInterface;

    private function journalingChange(): PendingChange
    {
        return new PendingChange(
            changeType: ChangeType::Add,
            dn: new Dn('cn=a,dc=example,dc=com'),
            entryUuid: '11111111-1111-4111-8111-111111111111',
            authzId: AuthzId::anonymous(),
        );
    }
}
