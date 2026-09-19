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
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoStorage;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Tests\Support\FreeDSx\Ldap\Pdo\EntryLinkFixtureTrait;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;
use Tests\Support\FreeDSx\Ldap\Storage\SubtreeRenameStorageContractTests;

final class PdoStorageTest extends TestCase
{
    use ServerContainerTrait;

    use EntryLinkFixtureTrait;

    use SubtreeRenameStorageContractTests;

    private PdoStorage $subject;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(PdoStorage::class);
    }

    /**
     * The SQL predicate has to answer the attribute's own EQUALITY rule, not a case-folded comparison.
     *
     * @param non-empty-string $attribute
     */
    #[DataProvider('rewrittenSpellingProvider')]
    public function test_a_value_matches_an_assertion_spelled_differently_under_its_matching_rule(
        string $attribute,
        string $stored,
        string $asserted,
    ): void {
        $this->subject->store(new Entry(
            new Dn('cn=spelling,dc=example,dc=com'),
            new Attribute('cn', 'spelling'),
            new Attribute($attribute, $stored),
        ));

        self::assertContains(
            'cn=spelling,dc=example,dc=com',
            $this->dnsMatching(
                $this->subject,
                Filters::equal($attribute, $asserted),
            ),
        );
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function rewrittenSpellingProvider(): iterable
    {
        yield 'distinguishedNameMatch ignores RDN spacing and case' => [
            'member',
            'CN=Alice, DC=Example, DC=Com',
            'cn=alice,dc=example,dc=com',
        ];
        yield 'uniqueMemberMatch ignores RDN spacing and case' => [
            'uniqueMember',
            'CN=Alice, DC=Example, DC=Com',
            'cn=alice,dc=example,dc=com',
        ];
        yield 'telephoneNumberMatch ignores hyphens and spaces' => [
            'telephoneNumber',
            '+1-408-555-1212',
            '+1 408 555 1212',
        ];
        yield 'numericStringMatch ignores spaces' => [
            'x121Address',
            '1111 2222',
            '11112222',
        ];
    }

    /**
     * Its only stored attribute type lives in the password policy schema, so this one needs both sources merged.
     */
    public function test_a_generalized_time_value_matches_an_assertion_naming_the_same_instant(): void
    {
        // The policy schema is added for pwdChangedTime, whose syntax decides how the value is indexed.
        $options = TestServerOptions::sqlite();
        $options->getSchemaConfig()
            ->addSource(SchemaResource::PasswordPolicy);
        $storage = $this->pdoStorage($options);

        $storage->store(new Entry(
            new Dn('cn=stamped,dc=example,dc=com'),
            new Attribute('cn', 'stamped'),
            new Attribute('pwdChangedTime', '20260101070000-0500'),
        ));

        self::assertSame(
            ['cn=stamped,dc=example,dc=com'],
            $this->dnsMatching(
                $storage,
                Filters::equal('pwdChangedTime', '20260101120000Z'),
            ),
        );
    }

    public function test_a_linked_value_follows_the_target_through_a_rename(): void
    {
        $this->linkAdminsToBob();

        $this->subject->renameSubtree(
            new Dn('cn=bob,dc=example,dc=com'),
            new Dn('cn=Robert,dc=example,dc=com'),
        );

        self::assertSame(
            ['cn=Robert,dc=example,dc=com'],
            $this->subject->find(new Dn('cn=admins,dc=example,dc=com'))
                ?->get('member')
                ?->getValues(),
        );
    }

    public function test_deleting_the_target_removes_it_from_the_linked_attribute(): void
    {
        $this->linkAdminsToBob();

        $this->subject->remove(new Dn('cn=bob,dc=example,dc=com'));

        self::assertNull(
            $this->subject->find(new Dn('cn=admins,dc=example,dc=com'))?->get('member'),
        );
    }

    public function test_atomic_commits_on_success(): void
    {
        $this->subject->atomic(function (): void {
            $this->storeNamed('Committed');
        });

        self::assertNotNull($this->subject->find(new Dn('cn=committed,dc=example,dc=com')));
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

        self::assertNull($this->subject->find(new Dn('cn=rollback,dc=example,dc=com')));
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

        self::assertNotNull($this->subject->find(new Dn('cn=outer,dc=example,dc=com')));
        self::assertNull($this->subject->find(new Dn('cn=inner,dc=example,dc=com')));
    }

    public function test_a_journal_append_rolls_back_with_the_enclosing_write_transaction(): void
    {
        $container = Container::forServer(
            TestServerOptions::sqlite()
                ->setChangeJournalConfig(new ChangeJournalConfig()),
        );
        $storage = $container->get(PdoStorage::class);
        $journal = $container->get(ChangeJournalInterface::class);

        try {
            $storage->atomic(static function () use ($journal): void {
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
     * The subject is the adapter rather than schema enforcement, so its fixtures are not held to one.
     */
    protected function makeServerOptions(): ServerOptions
    {
        return TestServerOptions::sqlite();
    }

    protected function makeRenameStorage(Entry ...$entries): EntryStorageInterface
    {
        $storage = $this->pdoStorage(TestServerOptions::sqlite());

        foreach ($entries as $entry) {
            $storage->store($entry);
        }

        return $storage;
    }

    private function pdoStorage(ServerOptions $options): PdoStorage
    {
        return $this->fromContainer(
            PdoStorage::class,
            options: $options,
        );
    }

    private function storeNamed(string $cn): void
    {
        $this->subject->store(new Entry(
            new Dn("cn={$cn},dc=example,dc=com"),
            new Attribute('cn', $cn),
        ));
    }

    /**
     * cn=Admins holding cn=Bob as a linked member.
     */
    private function linkAdminsToBob(): void
    {
        $this->storeNamed('Bob');
        $this->storeNamed('Admins');
        $this->linkTogether(
            $this->fromContainer(PdoConnection::class)->pdo(),
            'cn=admins,dc=example,dc=com',
            'cn=bob,dc=example,dc=com',
        );
    }

    /**
     * @return list<string>
     */
    private function dnsMatching(
        PdoStorage $storage,
        FilterInterface $filter,
    ): array {
        $dns = [];
        foreach ($storage->list(new StorageListOptions(new Dn('dc=example,dc=com'), true, $filter))->entries() as $entry) {
            $dns[] = $entry->getDn()->toString();
        }

        return $dns;
    }
}
