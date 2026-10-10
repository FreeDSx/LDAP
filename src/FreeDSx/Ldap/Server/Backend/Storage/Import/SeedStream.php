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

namespace FreeDSx\Ldap\Server\Backend\Storage\Import;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Ldif\LdifChangeRecord;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use Generator;

use function sprintf;

/**
 * Streams the entries of seed records to an import.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SeedStream
{
    private ?LdifChangeRecord $current = null;

    /**
     * @param iterable<LdifChangeRecord> $records
     */
    public function __construct(private readonly iterable $records) {}

    /**
     * @return Generator<Entry>
     * @throws RuntimeException when a record is not an add
     */
    public function entries(): Generator
    {
        foreach ($this->records as $record) {
            if (!$record->request instanceof AddRequest) {
                throw new RuntimeException(sprintf(
                    'seed() only accepts content records (adds). Use applyChanges() for modify/delete/rename (LDIF line %d).',
                    $record->line ?? 0,
                ));
            }
            $this->current = $record;

            yield $record->request->getEntry();
        }
        $this->current = null;
    }

    /**
     * The record whose entry was last handed over, or null once every one has been.
     */
    public function current(): ?LdifChangeRecord
    {
        return $this->current;
    }
}
