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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Pdo;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\TransactionalWriteInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

/**
 * What a write joins when it runs inside an atomic block, which no unit test can answer against a real database.
 */
final class PdoTransactionTest extends TestCase
{
    use ServerContainerTrait;

    private ReadEntryInterface $reader;

    private WriteEntryInterface $writer;

    private TransactionalWriteInterface $subject;

    protected function setUp(): void
    {
        $this->reader = $this->fromContainer(ReadEntryInterface::class);
        $this->writer = $this->fromContainer(WriteEntryInterface::class);
        $this->subject = $this->fromContainer(TransactionalWriteInterface::class);
    }

    public function test_atomic_commits_on_success(): void
    {
        $this->subject->atomic(function (): void {
            $this->storeNamed('Committed');
        });

        self::assertNotNull($this->reader->find(new Dn('cn=committed,dc=example,dc=com')));
    }

    public function test_atomic_rolls_back_on_exception(): void
    {
        try {
            $this->subject->atomic(function (): void {
                $this->storeNamed('Rollback');

                throw new RuntimeException('intentional');
            });
            self::fail('Expected the failure to surface.');
        } catch (RuntimeException) {
            // Expected, since the operation throws.
        }

        self::assertNull($this->reader->find(new Dn('cn=rollback,dc=example,dc=com')));
    }

    public function test_a_nested_atomic_block_rolls_back_only_its_own_writes(): void
    {
        $this->subject->atomic(function (): void {
            $this->storeNamed('Outer');

            try {
                $this->subject->atomic(function (): void {
                    $this->storeNamed('Inner');

                    throw new RuntimeException('inner fail');
                });
            } catch (RuntimeException) {
                // Swallowed, so only the inner block's writes are undone.
            }
        });

        self::assertNotNull($this->reader->find(new Dn('cn=outer,dc=example,dc=com')));
        self::assertNull($this->reader->find(new Dn('cn=inner,dc=example,dc=com')));
    }

    public function test_a_journal_append_rolls_back_with_the_enclosing_write_transaction(): void
    {
        $container = Container::forServer(
            TestServerOptions::sqlite()
                ->setChangeJournalConfig(new ChangeJournalConfig()),
        );
        $transaction = $container->get(TransactionalWriteInterface::class);
        $journal = $container->get(ChangeJournalInterface::class);

        try {
            $transaction->atomic(static function () use ($journal): void {
                $journal->append(new PendingChange(
                    changeType: ChangeType::Add,
                    dn: new Dn('cn=a,dc=example,dc=com'),
                    entryUuid: '11111111-1111-4111-8111-111111111111',
                    authzId: AuthzId::anonymous(),
                ));

                throw new RuntimeException('force rollback');
            });
        } catch (RuntimeException) {
            // Expected, since the operation throws.
        }

        self::assertSame(
            [],
            iterator_to_array($journal->read()),
        );
        self::assertSame(
            0,
            $journal->latestSeq(),
        );
    }

    /**
     * The subject is the transaction rather than schema enforcement, so its fixtures are not held to one.
     */
    protected function makeServerOptions(): ServerOptions
    {
        return TestServerOptions::sqlite();
    }

    private function storeNamed(string $cn): void
    {
        $this->writer->store(new Entry(
            new Dn("cn={$cn},dc=example,dc=com"),
            new Attribute('cn', $cn),
        ));
    }
}
