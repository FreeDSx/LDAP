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

namespace FreeDSx\Ldap\Server\Backend\Storage\Schema;

use FreeDSx\Ldap\Entry\Attribute;

use function array_keys;
use function array_unique;
use function array_values;
use function in_array;

/**
 * Which attributes reverse which linked ones.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class Backlinks
{
    /**
     * @param array<string, string> $reverses Every back-link name, aliases included, to the linked name it reverses.
     * @param array<string, string> $read The name each back-link is read under, to the linked name it reverses.
     */
    public function __construct(
        private array $reverses = [],
        private array $read = [],
    ) {}

    /**
     * The linked attribute a back-link reverses.
     *
     * @return ?string Null when it reverses none.
     */
    public function linkedBy(string $backlink): ?string
    {
        return $this->reverses[Attribute::normalizeName($backlink)] ?? null;
    }

    /**
     * The names a linked attribute's values are read back under. There may be more than one.
     *
     * @return list<string>
     */
    public function reversing(string $linked): array
    {
        $linked = Attribute::normalizeName($linked);
        $names = [];

        foreach ($this->read as $backlink => $reverses) {
            if ($reverses === $linked) {
                $names[] = $backlink;
            }
        }

        return $names;
    }

    /**
     * The linked attributes something reverses.
     *
     * @return list<string>
     */
    public function linkedNames(): array
    {
        return array_values(array_unique(array_values($this->read)));
    }

    /**
     * Every name values are read back under.
     *
     * @return list<string>
     */
    public function names(): array
    {
        return array_keys($this->read);
    }

    /**
     * Only the back-links among those named.
     *
     * @param list<string> $wanted
     */
    public function only(array $wanted): self
    {
        $read = [];

        foreach ($this->read as $backlink => $reverses) {
            if (in_array($backlink, $wanted, true)) {
                $read[$backlink] = $reverses;
            }
        }

        return new self(
            $this->reverses,
            $read,
        );
    }

    public function isEmpty(): bool
    {
        return $this->read === [];
    }
}
