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

namespace FreeDSx\Ldap\Container\Provider;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\EntryIndexReindexer;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Schema\Matching\EqualityComparatorResolver;
use FreeDSx\Ldap\Schema\Validation\SchemaValidator;
use FreeDSx\Ldap\Schema\Validation\Syntax\AttributeSyntaxResolver;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query\EntryLister;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query\EntryReader;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support\SortKeyComparator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\SerializedEntryWriter;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Writer\EntryLinkWriter;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Writer\PendingLinkWriter;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\EntryLinks;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\LinkedValueLookupInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\NoLinkedValues;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\ReferenceIntegrityInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\ResolvedReferences;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\RowLockableInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\UnlockedRows;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\LinkedLeafWitness;
use FreeDSx\Ldap\Server\Backend\Write\Operation\LinkedChanges;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ListEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\TransactionalWriteInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Audit\AuditingChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\InMemoryChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\PdoChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeContext;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeContextInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeIndexForms;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use FreeDSx\Ldap\Server\Backend\Storage\Search\StorageListOptionsFactory;
use FreeDSx\Ldap\Server\Config\Storage\InMemoryStorageConfig;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\ServerOptions;

/**
 * Builds the storage adapter selected by the StorageConfigInterface, plus the schema answers every adapter shares.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class StorageContainerProvider implements ContainerProviderInterface
{
    public function factories(): array
    {
        return [
            AttributeContextInterface::class => $this->makeAttributeContext(...),
            AttributeIndexForms::class => $this->makeAttributeIndexForms(...),
            LinkedAttributes::class => $this->makeLinkedAttributes(...),
            SortKeyComparator::class => $this->makeSortKeyComparator(...),
            StorageListOptionsFactory::class => $this->makeStorageListOptionsFactory(...),
            InMemoryStorage::class => $this->makeInMemoryStorage(...),
            ReadEntryInterface::class => $this->makeReads(...),
            ListEntryInterface::class => $this->makeLists(...),
            WriteEntryInterface::class => $this->makeWrites(...),
            TransactionalWriteInterface::class => $this->makeTransaction(...),
            RowLockableInterface::class => $this->makeRowLocks(...),
            ReferenceIntegrityInterface::class => $this->makeReferenceIntegrity(...),
            LinkedValueLookupInterface::class => $this->makeLinkedValueLookup(...),
            LinkedLeafWitness::class => $this->makeLinkedLeafWitness(...),
            LinkedChanges::class => $this->makeLinkedChanges(...),
            EntryIndexReindexer::class => $this->makeEntryIndexReindexer(...),
            ChangeJournalInterface::class => $this->makeChangeJournal(...),
        ];
    }

    private function makeReads(Container $container): ReadEntryInterface
    {
        return $this->isPdo($container)
            ? $container->get(EntryReader::class)
            : $container->get(InMemoryStorage::class);
    }

    private function makeLists(Container $container): ListEntryInterface
    {
        return $this->isPdo($container)
            ? $container->get(EntryLister::class)
            : $container->get(InMemoryStorage::class);
    }

    /**
     * Writes reach PDO through the serializing writer, which is what keeps them on a single connection.
     */
    private function makeWrites(Container $container): WriteEntryInterface
    {
        return $this->isPdo($container)
            ? $container->get(SerializedEntryWriter::class)
            : $container->get(InMemoryStorage::class);
    }

    /**
     * The same writer answers this, so a transaction opens on the connection its writes are already routed to.
     */
    private function makeTransaction(Container $container): TransactionalWriteInterface
    {
        return $this->isPdo($container)
            ? $container->get(SerializedEntryWriter::class)
            : $container->get(InMemoryStorage::class);
    }

    /**
     * The per-entry lock a write takes, or a stand-in for storage whose writes never run concurrently.
     */
    private function makeRowLocks(Container $container): RowLockableInterface
    {
        return $this->isPdo($container)
            ? $container->get(SerializedEntryWriter::class)
            : new UnlockedRows($container->get(ReadEntryInterface::class));
    }

    /**
     * In memory storage keeps values as written, so nothing it holds can be left unresolved.
     */
    private function makeReferenceIntegrity(Container $container): ReferenceIntegrityInterface
    {
        return $this->isPdo($container)
            ? $container->get(PendingLinkWriter::class)
            : new ResolvedReferences();
    }

    private function makeLinkedValueLookup(Container $container): LinkedValueLookupInterface
    {
        return $this->isPdo($container)
            ? $container->get(EntryLinks::class)
            : new NoLinkedValues();
    }

    private function makeLinkedChanges(Container $container): LinkedChanges
    {
        return new LinkedChanges(
            $container->get(LinkedAttributes::class),
            $this->isPdo($container)
                ? $container->get(EntryLinkWriter::class)
                : $container->get(InMemoryStorage::class),
            $container->get(SchemaValidator::class),
        );
    }

    private function makeLinkedLeafWitness(Container $container): LinkedLeafWitness
    {
        return new LinkedLeafWitness(
            $container->get(LinkedValueLookupInterface::class),
            $container->get(LinkedAttributes::class),
        );
    }

    private function makeEntryIndexReindexer(Container $container): EntryIndexReindexer
    {
        return new EntryIndexReindexer(
            $container->get(ReadEntryInterface::class),
            $container->get(ListEntryInterface::class),
            $container->get(WriteEntryInterface::class),
            $container->get(TransactionalWriteInterface::class),
        );
    }

    /**
     * The schema derived answers the filter translators and the sort-spec builder need about an attribute.
     */
    private function makeAttributeContext(Container $container): AttributeContextInterface
    {
        $schema = $container->get(ServerOptions::class)->getSchema();

        return new AttributeContext(
            $schema,
            new AttributeSyntaxResolver($schema),
        );
    }

    /**
     * The types the schema declares as links, shared by hydration, the write path and the filter translators.
     */
    private function makeLinkedAttributes(Container $container): LinkedAttributes
    {
        $linked = new LinkedAttributes($container->get(ServerOptions::class)->getSchema());
        $linked->assertNoneRequired();

        return $linked;
    }

    /**
     * The index forms a store must key values by for its index to answer the rule the evaluator applies.
     */
    private function makeAttributeIndexForms(Container $container): AttributeIndexForms
    {
        $schema = $container->get(ServerOptions::class)->getSchema();

        return new AttributeIndexForms(
            $schema,
            $container->get(EqualityComparatorResolver::class),
        );
    }

    private function makeSortKeyComparator(Container $container): SortKeyComparator
    {
        return new SortKeyComparator($container->get(ServerOptions::class)->getSchema());
    }

    private function makeStorageListOptionsFactory(Container $container): StorageListOptionsFactory
    {
        $options = $container->get(ServerOptions::class);

        return new StorageListOptionsFactory(
            $options->getSchema(),
            $options->makeSearchLimits(),
            $container->get(LinkedAttributes::class),
        );
    }

    /**
     * One instance answers every storage contract, so the entries it holds are not split across several stores.
     *
     * @throws RuntimeException when the configured storage is not one this builds
     */
    private function makeInMemoryStorage(Container $container): InMemoryStorage
    {
        $config = $container->get(ServerOptions::class)->getStorageConfig();

        if (!$config instanceof InMemoryStorageConfig) {
            throw new RuntimeException(sprintf(
                'Unsupported storage config "%s".',
                $config::class,
            ));
        }

        return new InMemoryStorage(
            $config->entries(),
            $container->get(SortKeyComparator::class),
        );
    }

    private function isPdo(Container $container): bool
    {
        return $container->get(ServerOptions::class)->getStorageConfig() instanceof PdoConfig;
    }

    /**
     * The journal the configured storage records its changes in; only resolvable while journaling is enabled.
     *
     * @throws RuntimeException when no change journal is configured
     */
    private function makeChangeJournal(Container $container): ChangeJournalInterface
    {
        $options = $container->get(ServerOptions::class);
        $journalConfig = $options->getChangeJournalConfig()
            ?? throw new RuntimeException('No change journal is configured.');

        return AuditingChangeJournal::wrap(
            $options->getStorageConfig() instanceof PdoConfig
                ? $container->get(PdoChangeJournal::class)
                : new InMemoryChangeJournal($options->getReplicationConfig()->getId()),
            $journalConfig,
        );
    }
}
