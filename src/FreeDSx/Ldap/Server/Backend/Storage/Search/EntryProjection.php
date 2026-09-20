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

namespace FreeDSx\Ldap\Server\Backend\Storage\Search;

use function array_fill_keys;

/**
 * What a read materializes: which attributes, how many values of a linked attribute, and whether it has children.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class EntryProjection
{
    /**
     * Linked values read per attribute when the caller names no bound of its own.
     */
    public const DEFAULT_LINK_CAP = 1500;

    /**
     * @param list<string>|null $attributes Lowercase base attribute names to materialize, or null for all.
     * @param ?int $linkCap Values read per linked attribute: null for every value, zero for none of them.
     * @param bool $withHasSubordinates Whether a read able to answer hasSubordinates alongside the row should.
     */
    public function __construct(
        public ?array $attributes = null,
        public ?int $linkCap = self::DEFAULT_LINK_CAP,
        public bool $withHasSubordinates = false,
    ) {}

    /**
     * Every value of every linked attribute, for callers that write back what they read or hand it to a replica.
     *
     * @param list<string>|null $attributes
     */
    public static function unbounded(?array $attributes = null): self
    {
        return new self(
            $attributes,
            null,
        );
    }

    /**
     * The base names to materialize as a set, or null for every attribute.
     *
     * @return array<string, true>|null
     */
    public function allowed(): ?array
    {
        return $this->attributes === null
            ? null
            : array_fill_keys(
                $this->attributes,
                true,
            );
    }
}
