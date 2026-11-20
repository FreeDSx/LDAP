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

namespace Tests\Support\FreeDSx\Ldap\Sync\Convergence;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ListEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;

use function array_filter;
use function array_values;
use function ksort;
use function sort;
use function strtolower;

/**
 * Where each entry sits, what it holds and whom each group names, as two sides of a sync compare them.
 */
final readonly class DirectorySnapshot
{
    private const MEMBER = 'member';

    /**
     * Attributes each read computes, which a replica keeps as sent while its provider stores none of them.
     */
    private const COMPUTED = [
        'entrydn' => true,
        'hassubordinates' => true,
        'subschemasubentry' => true,
        'memberof' => true,
    ];

    /**
     * @param array<string, string> $dns The normalized DN of each entry, keyed by lowercased entryUUID.
     * @param array<string, list<string>> $members The normalized member values of each group, keyed the same way.
     * @param array<string, array<string, list<string>>> $attributes Each entry's other attributes, keyed the same way.
     */
    private function __construct(
        public array $dns,
        public array $members,
        public array $attributes,
    ) {}

    /**
     * Everything stored, which a replica should hold only when its provider shows it.
     */
    public static function of(ListEntryInterface $lister): self
    {
        return self::read(
            $lister,
            false,
        );
    }

    /**
     * What the sync identity can see, which leaves out the hidden subtree.
     */
    public static function visibleIn(ListEntryInterface $lister): self
    {
        return self::read(
            $lister,
            true,
        );
    }

    /**
     * Whether the normalized DN is the hidden subtree or under it.
     */
    public static function isHidden(Dn $dn): bool
    {
        $hidden = (new Dn(ConvergenceProvider::HIDDEN))->normalize();

        return $dn->toString() === $hidden->toString()
            || $dn->isDescendantOf($hidden);
    }

    /**
     * The same snapshot without the member values that name the given entries.
     *
     * @param array<string, true> $uuids keyed by lowercased entryUUID
     */
    public function withoutMembersNaming(array $uuids): self
    {
        $excluded = $this->dnsOf($uuids);
        $members = [];

        foreach ($this->members as $group => $values) {
            $kept = array_values(array_filter(
                $values,
                static fn(string $value): bool => !isset($excluded[$value]),
            ));

            if ($kept !== []) {
                $members[$group] = $kept;
            }
        }

        return new self(
            $this->dns,
            $members,
            $this->attributes,
        );
    }

    /**
     * @param array<string, true> $uuids
     *
     * @return array<string, true>
     */
    private function dnsOf(array $uuids): array
    {
        $dns = [];

        foreach ($this->dns as $uuid => $dn) {
            if (isset($uuids[$uuid])) {
                $dns[$dn] = true;
            }
        }

        return $dns;
    }

    private static function read(
        ListEntryInterface $lister,
        bool $visibleOnly,
    ): self {
        $dns = [];
        $members = [];
        $attributes = [];

        foreach (self::entries($lister) as $entry) {
            $dn = $entry->getDn()->normalize();

            if ($visibleOnly && self::isHidden($dn)) {
                continue;
            }
            $uuid = strtolower($entry->getUuidOrFail());
            $dns[$uuid] = $dn->toString();
            $attributes[$uuid] = self::attributesOf($entry);
            $members[$uuid] = self::visibleValues($entry->get(self::MEMBER)?->getValues() ?? []);
        }

        return new self(
            self::sorted($dns),
            self::sorted(array_filter($members)),
            self::sorted($attributes),
        );
    }

    /**
     * @return iterable<Entry>
     */
    private static function entries(ListEntryInterface $lister): iterable
    {
        $options = StorageListOptions::matchAll(
            new Dn(''),
            subtree: true,
            projection: new EntryProjection(linkCap: null),
        );

        return $lister->list($options)->entries();
    }

    /**
     * @return array<string, list<string>>
     */
    private static function attributesOf(Entry $entry): array
    {
        $attributes = [];

        foreach ($entry->getAttributes() as $attribute) {
            $name = Attribute::normalizeName($attribute->getName());

            if ($name === self::MEMBER || isset(self::COMPUTED[$name])) {
                continue;
            }
            $values = array_values($attribute->getValues());
            sort($values);
            $attributes[$name] = $values;
        }

        return self::sorted($attributes);
    }

    /**
     * @param array<string> $values
     *
     * @return list<string>
     */
    private static function visibleValues(array $values): array
    {
        $visible = [];

        foreach ($values as $value) {
            $dn = (new Dn($value))->normalize();

            if (!self::isHidden($dn)) {
                $visible[] = $dn->toString();
            }
        }
        sort($visible);

        return $visible;
    }

    /**
     * @template T
     *
     * @param array<string, T> $values
     *
     * @return array<string, T>
     */
    private static function sorted(array $values): array
    {
        ksort($values);

        return $values;
    }
}
