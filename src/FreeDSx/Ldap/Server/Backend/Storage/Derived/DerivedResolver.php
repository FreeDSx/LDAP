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

namespace FreeDSx\Ldap\Server\Backend\Storage\Derived;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\GeneratedEntry;

/**
 * Produces the operational attributes computed per read, so the read and filter paths share one definition.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class DerivedResolver
{
    public function __construct(private EntryStorageInterface $storage) {}

    /**
     * @param string $name A canonical type name, which callers get from {@see DerivedAttributeTrait}.
     * @throws InvalidArgumentException when the type is not derived.
     */
    public function resolve(
        string $name,
        Entry $entry,
    ): string {
        return match ($name) {
            // RFC 5020: derived on read so a rename cannot leave it stale.
            AttributeTypeOid::NAME_ENTRY_DN => $entry->getDn()->toString(),
            // RFC 4512 §4.2: how a client locates the schema governing this entry.
            AttributeTypeOid::NAME_SUBSCHEMA_SUBENTRY => GeneratedEntry::Subschema->value,
            // X.501: the one derived value needing a lookup rather than the entry alone.
            AttributeTypeOid::NAME_HAS_SUBORDINATES => $this->storage->hasChildren($entry->getDn())
                ? 'TRUE'
                : 'FALSE',
            default => throw new InvalidArgumentException("Unsupported derived attribute: $name"),
        };
    }
}
