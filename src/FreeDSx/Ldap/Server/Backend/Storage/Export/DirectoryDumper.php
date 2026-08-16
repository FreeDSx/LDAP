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

namespace FreeDSx\Ldap\Server\Backend\Storage\Export;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Ldif\LdifWriter;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use Generator;

/**
 * Streams the entries of a storage backend as LDIF content-record chunks for backup/export.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class DirectoryDumper
{
    /**
     * @param list<Dn> $namingContexts dump roots when DumpOptions::baseDn is not set
     */
    public function __construct(
        private EntryStorageInterface $storage,
        private array $namingContexts,
        private FilterEvaluatorInterface $filterEvaluator,
        private LdifWriter $writer = new LdifWriter(),
    ) {}

    /**
     * @return iterable<string>
     */
    public function dump(DumpOptions $options = new DumpOptions()): iterable
    {
        $header = $this->writer->versionHeader();

        if ($header !== '') {
            yield $header;
        }

        $filter = $options->getFilter();

        foreach ($this->resolveBases($options) as $base) {
            yield from $this->streamNamingContext(
                $base,
                $filter,
            );
        }
    }

    /**
     * @return list<Dn>
     */
    private function resolveBases(DumpOptions $options): array
    {
        if ($options->getBaseDn() !== null) {
            return [$options->getBaseDn()];
        }

        return $this->namingContexts;
    }

    /**
     * Stream the entries from a naming context to LDIF.
     *
     * @return Generator<string>
     */
    private function streamNamingContext(
        Dn $base,
        ?FilterInterface $filter,
    ): Generator {
        $listOptions = new StorageListOptions(
            baseDn: $base,
            subtree: true,
            filter: $filter ?? new AndFilter(),
        );
        $stream = $this->storage->list($listOptions);

        foreach ($stream->entries as $entry) {
            if (!$stream->isPreFiltered && $filter !== null) {
                if (!$this->filterEvaluator->evaluate($entry, $filter)) {
                    continue;
                }
            }

            yield $this->writer->writeOne(Operations::add($entry));
        }
    }
}
