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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;

/**
 * Converts between an entry and the row that stores it.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class EntryRowCodec
{
    /**
     * The attribute blob stored in an entry's row.
     */
    public function encode(Entry $entry): string
    {
        $attributes = [];

        foreach ($entry->getAttributes() as $attribute) {
            $attributes[$attribute->getDescription()] = array_values($attribute->getValues());
        }

        return serialize($attributes);
    }

    /**
     * @param array<array-key, mixed> $row
     * @param array<string, true>|null $allowed Base names to materialize, or null for all.
     * @param array<string, list<string>> $links Already fetched link values, keyed by lowercased attribute name.
     *
     * @throws StorageIoException when the row's attribute blob cannot be decoded
     */
    public function decode(
        array $row,
        ?array $allowed = null,
        array $links = [],
    ): Entry {
        $dn = new Dn(isset($row['dn']) && is_string($row['dn'])
            ? $row['dn']
            : '');

        // A projection that materializes nothing, such as a 1.1 request, never reads the blob.
        if ($allowed === []) {
            return Entry::raw(
                $dn,
                [],
            );
        }

        $attributes = [
            ...$this->storedAttributes(
                $row,
                $allowed,
            ),
            ...$this->linkedAttributes(
                $links,
                $allowed,
            ),
        ];

        // Present only when the query projected it. This spares the resolver a query per entry.
        if (isset($row['has_children'])) {
            $attributes[] = new Attribute(
                AttributeTypeOid::NAME_HAS_SUBORDINATES,
                $row['has_children'] ? 'TRUE' : 'FALSE',
            );
        }

        return Entry::raw(
            $dn,
            $attributes,
        );
    }

    /**
     * @param array<array-key, mixed> $row
     * @param array<string, true>|null $allowed
     *
     * @return list<Attribute>
     *
     * @throws StorageIoException
     */
    private function storedAttributes(
        array $row,
        ?array $allowed,
    ): array {
        $blob = isset($row['attributes']) && is_string($row['attributes'])
            ? $row['attributes']
            : 'a:0:{}';

        /** @var array<string, list<string>>|false $raw Trusted: written by {@see encode()} from {@see Attribute::getValues()}: string[]. */
        $raw = @unserialize(
            $blob,
            ['allowed_classes' => false],
        );

        if (!is_array($raw)) {
            throw new StorageIoException('Failed to decode entry attributes; storage row is corrupted.');
        }
        $attributes = [];

        foreach ($raw as $name => $values) {
            if ($allowed !== null && !isset($allowed[Attribute::normalizeName($name)])) {
                continue;
            }

            $attributes[] = Attribute::fromArray(
                $name,
                $values,
            );
        }

        return $attributes;
    }

    /**
     * @param array<string, list<string>> $links
     * @param array<string, true>|null $allowed
     *
     * @return list<Attribute>
     */
    private function linkedAttributes(
        array $links,
        ?array $allowed,
    ): array {
        $attributes = [];

        foreach ($links as $name => $values) {
            if ($allowed !== null && !isset($allowed[$name])) {
                continue;
            }

            $attributes[] = Attribute::fromArray(
                $name,
                $values,
            );
        }

        return $attributes;
    }
}
