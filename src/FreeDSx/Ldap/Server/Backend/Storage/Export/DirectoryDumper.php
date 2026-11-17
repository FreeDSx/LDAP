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
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Ldif\LdifWriter;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Directory\SubtreeEnumerator;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\LinkedLeafWitness;
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
        private SubtreeEnumerator $subtree,
        private array $namingContexts,
        private FilterEvaluatorInterface $filterEvaluator,
        private LinkedLeafWitness $linkedLeaves,
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
        $separator = '';

        foreach ($this->resolveBases($options) as $base) {
            $records = $this->streamNamingContext(
                $base,
                $filter,
            );

            foreach ($records as $record) {
                yield $separator . $record;
                $separator = $this->writer->recordSeparator();
            }
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
     * Stream the entries from a naming context to LDIF, each parent before its children so the output seeds back.
     *
     * @return Generator<string>
     */
    private function streamNamingContext(
        Dn $base,
        ?FilterInterface $filter,
    ): Generator {
        // @todo An export needs every value, but each is held at once; stream linked values in chunks as they are written.
        foreach ($this->subtree->parentsFirst($base) as $entry) {
            if ($filter !== null && !$this->matches($entry, $filter)) {
                continue;
            }

            yield $this->writer->writeOne(Operations::add($entry));
        }
    }

    /**
     * Judged with the back-links the filter names, which the walk does not read.
     */
    private function matches(
        Entry $entry,
        FilterInterface $filter,
    ): bool {
        return $this->filterEvaluator->evaluate(
            $this->linkedLeaves->witness(
                $entry,
                $filter,
            ),
            $filter,
        );
    }
}
