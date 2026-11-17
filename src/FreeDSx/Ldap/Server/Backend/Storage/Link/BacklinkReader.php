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

namespace FreeDSx\Ldap\Server\Backend\Storage\Link;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\Backlinks;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;

use function in_array;

/**
 * Reads the back-links a selection asks for onto an entry.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class BacklinkReader
{
    /**
     * @param ?int $linkCap Values read per back-link: null for every value.
     */
    public function __construct(
        private ReadEntryInterface $storage,
        private Backlinks $backlinks,
        private ?int $linkCap = EntryProjection::DEFAULT_LINK_CAP,
    ) {}

    /**
     * The entry with the back-links the selection names, by name or through every operational attribute.
     *
     * @param array<Attribute> $selection
     */
    public function withSelected(
        Entry $entry,
        array $selection,
    ): Entry {
        $names = $this->backlinks->selectedBy($selection);
        if ($names === []) {
            return $entry;
        }
        $stored = $this->storage->find(
            $entry->getDn(),
            new EntryProjection(
                attributes: $names,
                linkCap: $this->linkCap,
                backlinks: $names,
            ),
        );

        foreach ($stored?->getAttributes() ?? [] as $attribute) {
            if (in_array(Attribute::normalizeName($attribute->getName()), $names, true)) {
                $entry->set($attribute);
            }
        }

        return $entry;
    }
}
