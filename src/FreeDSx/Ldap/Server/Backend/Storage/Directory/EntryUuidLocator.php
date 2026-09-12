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

namespace FreeDSx\Ldap\Server\Backend\Storage\Directory;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;

/**
 * Locates an entry by its entryUUID.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class EntryUuidLocator
{
    public function __construct(
        private EntryStorageInterface $storage,
        private FilterEvaluatorInterface $filterEvaluator,
    ) {}

    /**
     * The entry carrying $uuid, or null when this storage holds it nowhere.
     */
    public function findByUuid(string $uuid): ?Entry
    {
        $filter = Filters::equal(
            AttributeTypeOid::NAME_ENTRY_UUID,
            $uuid,
        );
        $stream = $this->storage->list(new StorageListOptions(
            baseDn: new Dn(''),
            subtree: true,
            filter: $filter,
        ));

        // A listing guarantees scope only
        // the filter is evaluated here unless storage already applied it exactly.
        foreach ($stream->entries() as $entry) {
            if ($stream->isPreFiltered || $this->filterEvaluator->evaluate($entry, $filter)) {
                return $entry;
            }
        }

        return null;
    }
}
