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

use function array_keys;
use function array_merge;
use function array_values;

/**
 * The linked values a write adds and removes, carried instead of the attribute it changes.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class LinkDelta
{
    /**
     * @var array<string, list<string>>
     */
    private array $added;

    /**
     * @var array<string, list<string>>
     */
    private array $removed;

    /**
     * @param array<string, list<string>> $added Values to link, keyed by lowercased attribute name.
     * @param array<string, list<string>> $removed Values to unlink, keyed the same way.
     */
    public function __construct(
        array $added = [],
        array $removed = [],
        private bool $untouched = false,
    ) {
        $this->added = self::keyed($added);
        $this->removed = self::keyed($removed);
    }

    /**
     * Leaves the stored links as they are, for a write whose entry was read without them.
     */
    public static function untouched(): self
    {
        return new self(untouched: true);
    }

    /**
     * Whether the entry says nothing about its links, which a write storing one read without them does not.
     */
    public function isUntouched(): bool
    {
        return $this->untouched;
    }

    /**
     * Nothing to apply, which is what every write that changes no linked value carries.
     */
    public function isEmpty(): bool
    {
        return $this->added === [] && $this->removed === [];
    }

    /**
     * The attribute names the delta touches, added or removed.
     *
     * @return list<string>
     */
    public function names(): array
    {
        return array_values(array_unique(array_merge(
            array_keys($this->added),
            array_keys($this->removed),
        )));
    }

    /**
     * @return list<string>
     */
    public function added(string $name): array
    {
        return $this->added[Attribute::normalizeName($name)] ?? [];
    }

    /**
     * @return list<string>
     */
    public function removed(string $name): array
    {
        return $this->removed[Attribute::normalizeName($name)] ?? [];
    }

    /**
     * @param array<string, list<string>> $values
     *
     * @return array<string, list<string>>
     */
    private static function keyed(array $values): array
    {
        $keyed = [];

        foreach ($values as $name => $attributeValues) {
            if ($attributeValues === []) {
                continue;
            }

            $keyed[Attribute::normalizeName($name)] = array_values($attributeValues);
        }

        return $keyed;
    }
}
