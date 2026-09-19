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
use FreeDSx\Ldap\Schema\Validation\Syntax\AttributeSyntaxResolver;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support\SortKeyComparator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\WriteSerializingStorage;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
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
            EntryStorageInterface::class => $this->makeStorage(...),
            EntryIndexReindexer::class => $this->makeEntryIndexReindexer(...),
            ChangeJournalInterface::class => $this->makeChangeJournal(...),
        ];
    }

    private function makeEntryIndexReindexer(Container $container): EntryIndexReindexer
    {
        return new EntryIndexReindexer($container->get(EntryStorageInterface::class));
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
        return new LinkedAttributes($container->get(ServerOptions::class)->getSchema());
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
        );
    }

    /**
     * Build the runner-appropriate storage backend from the configured StorageConfigInterface.
     */
    private function makeStorage(Container $container): EntryStorageInterface
    {
        $options = $container->get(ServerOptions::class);
        $config = $options->getStorageConfig();

        return match (true) {
            $config instanceof PdoConfig => $container->get(WriteSerializingStorage::class),
            $config instanceof InMemoryStorageConfig => new InMemoryStorage(
                $config->entries(),
                $container->get(SortKeyComparator::class),
            ),
            default => throw new RuntimeException(sprintf(
                'Unsupported storage config "%s".',
                $config::class,
            )),
        };
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
