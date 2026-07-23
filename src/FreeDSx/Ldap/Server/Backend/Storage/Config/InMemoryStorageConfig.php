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

namespace FreeDSx\Ldap\Server\Backend\Storage\Config;

use FreeDSx\Ldap\Entry\Entry;

/**
 * Backs the server with a transient in-memory directory, optionally pre-seeded with entries.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class InMemoryStorageConfig implements StorageConfigInterface
{
    /**
     * @param Entry[] $entries
     */
    private function __construct(private array $entries) {}

    /**
     * @param Entry[] $entries pre-populated into the store
     */
    public static function withEntries(array $entries = []): self
    {
        return new self($entries);
    }

    /**
     * @return Entry[]
     */
    public function entries(): array
    {
        return $this->entries;
    }

    public function type(): StorageType
    {
        return StorageType::InMemory;
    }
}
