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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Write\Operation;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\InMemoryChangeJournal;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteSubtreeCommand;
use FreeDSx\Ldap\Server\Backend\Write\Operation\DeleteSubtreeHandler;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Backend\Write\WriteHandlerTestTrait;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class DeleteSubtreeHandlerTest extends TestCase
{
    use WriteHandlerTestTrait;

    private AccessControlInterface&MockObject $accessControl;

    protected function setUp(): void
    {
        $this->subtreeGraph();
    }

    public function test_it_removes_the_entry_and_all_descendants(): void
    {
        $this->deleteSubtree('ou=people,dc=example,dc=com');

        self::assertNull($this->find('ou=people,dc=example,dc=com'));
        self::assertNull($this->find('cn=alice,ou=people,dc=example,dc=com'));
        self::assertNull($this->find('cn=bob,ou=people,dc=example,dc=com'));
        self::assertNotNull($this->find('dc=example,dc=com'));
    }

    public function test_it_reaches_a_deeply_nested_subtree(): void
    {
        $this->subtreeGraph(new InMemoryStorage([
            new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example')),
            new Entry(new Dn('ou=people,dc=example,dc=com'), new Attribute('ou', 'people')),
            new Entry(new Dn('ou=staff,ou=people,dc=example,dc=com'), new Attribute('ou', 'staff')),
            new Entry(new Dn('cn=deep,ou=staff,ou=people,dc=example,dc=com'), new Attribute('cn', 'deep')),
        ]));

        $this->deleteSubtree('ou=people,dc=example,dc=com');

        self::assertNull($this->find('ou=people,dc=example,dc=com'));
        self::assertNull($this->find('ou=staff,ou=people,dc=example,dc=com'));
        self::assertNull($this->find('cn=deep,ou=staff,ou=people,dc=example,dc=com'));
        self::assertNotNull($this->find('dc=example,dc=com'));
    }

    public function test_it_authorizes_every_entry(): void
    {
        $seen = [];
        $this->accessControl
            ->method('authorizeOperation')
            ->willReturnCallback(static function (
                OperationType $operation,
                TokenInterface $token,
                Dn $dn,
            ) use (&$seen): void {
                $seen[] = $dn->toString();
            });

        $this->deleteSubtree('ou=people,dc=example,dc=com');

        sort($seen);
        self::assertSame(
            [
                'cn=alice,ou=people,dc=example,dc=com',
                'cn=bob,ou=people,dc=example,dc=com',
                'ou=people,dc=example,dc=com',
            ],
            $seen,
        );
    }

    public function test_a_denial_removes_nothing(): void
    {
        $this->accessControl
            ->method('authorizeOperation')
            ->willReturnCallback(static function (
                OperationType $operation,
                TokenInterface $token,
                Dn $dn,
            ): void {
                if (str_contains($dn->toString(), 'cn=bob')) {
                    throw new OperationException(
                        'denied',
                        ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                    );
                }
            });

        try {
            $this->deleteSubtree('ou=people,dc=example,dc=com');
            self::fail('Expected OperationException was not thrown.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                $e->getCode(),
            );
        }

        self::assertNotNull($this->find('ou=people,dc=example,dc=com'));
        self::assertNotNull($this->find('cn=alice,ou=people,dc=example,dc=com'));
        self::assertNotNull($this->find('cn=bob,ou=people,dc=example,dc=com'));
    }

    public function test_a_privileged_write_authorizes_nothing_separately(): void
    {
        $this->accessControl
            ->expects(self::never())
            ->method('authorizeOperation');

        $this->deleteSubtree(
            'ou=people,dc=example,dc=com',
            privileged: true,
        );

        self::assertNull($this->find('ou=people,dc=example,dc=com'));
    }

    public function test_it_refuses_a_naming_context_base(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $this->deleteSubtree('dc=example,dc=com');
    }

    public function test_it_refuses_a_base_that_does_not_exist(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->deleteSubtree('ou=missing,dc=example,dc=com');
    }

    public function test_it_journals_every_entry_with_its_pre_image(): void
    {
        $journal = $this->journaledGraph();
        foreach ([
            'ou=people,dc=example,dc=com',
            'cn=alice,ou=people,dc=example,dc=com',
            'cn=bob,ou=people,dc=example,dc=com',
        ] as $dn) {
            $this->seed($dn);
        }

        $this->deleteSubtree('ou=people,dc=example,dc=com');

        $deletes = array_values(array_filter(
            iterator_to_array($journal->read()),
            static fn(ChangeRecord $record): bool => $record->change->changeType === ChangeType::Delete,
        ));
        $dns = array_map(
            static fn(ChangeRecord $record): string => $record->change->dn->toString(),
            $deletes,
        );
        sort($dns);

        self::assertSame(
            [
                'cn=alice,ou=people,dc=example,dc=com',
                'cn=bob,ou=people,dc=example,dc=com',
                'ou=people,dc=example,dc=com',
            ],
            $dns,
        );
        foreach ($deletes as $record) {
            self::assertNotNull($record->change->preImage);
        }
    }

    /**
     * Validation is opted into by the tests that assert on it, rather than applied to every fixture here.
     */
    protected function makeServerOptions(): ServerOptions
    {
        return TestServerOptions::unvalidatedCore();
    }

    private function deleteSubtree(
        string $dn,
        bool $privileged = false,
    ): void {
        $this->graph->get(DeleteSubtreeHandler::class)->handle(
            new DeleteSubtreeCommand(new Dn($dn)),
            $privileged
                ? $this->systemContext()
                : $this->context(),
        );
    }

    private function subtreeGraph(?EntryStorageInterface $storage = null): void
    {
        $this->accessControl = $this->createMock(AccessControlInterface::class);
        $this->writeGraph(
            $storage ?? new InMemoryStorage([
                new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example')),
                new Entry(new Dn('ou=people,dc=example,dc=com'), new Attribute('ou', 'people')),
                new Entry(new Dn('cn=alice,ou=people,dc=example,dc=com'), new Attribute('cn', 'alice')),
                new Entry(new Dn('cn=bob,ou=people,dc=example,dc=com'), new Attribute('cn', 'bob')),
            ]),
            sharedInstances: [AccessControlInterface::class => $this->accessControl],
        );
    }

    private function journaledGraph(): InMemoryChangeJournal
    {
        $journal = new InMemoryChangeJournal();
        $this->accessControl = $this->createMock(AccessControlInterface::class);

        // Seeded directly so only the operations under test are journaled.
        $this->writeGraph(
            new InMemoryStorage(
                [new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example'))],
                $journal,
            ),
            TestServerOptions::unvalidatedCore()
                ->setChangeJournalConfig(new ChangeJournalConfig()),
            [AccessControlInterface::class => $this->accessControl],
        );

        return $journal;
    }

    private function seed(string $dn): void
    {
        $this->adds()->handle(
            new AddCommand(new Entry(
                new Dn($dn),
                new Attribute('objectClass', 'person'),
                new Attribute('cn', 'seed'),
            )),
            $this->context(),
        );
    }
}
