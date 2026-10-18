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

namespace FreeDSx\Ldap\Schema\Validation;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Operation\OperationType;

use function array_map;
use function array_values;

/**
 * The entry a write leaves behind, and what the client supplied to get there.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SchemaWrite
{
    /**
     * @param Change[] $changes
     * @param bool $isSystem Whether the server initiated the write.
     */
    private function __construct(
        public OperationType $operation,
        public Entry $entry,
        public array $changes,
        public bool $isSystem,
    ) {}

    public static function add(
        Entry $entry,
        bool $isSystem = false,
    ): self {
        return new self(
            OperationType::Add,
            $entry,
            [],
            $isSystem,
        );
    }

    /**
     * @param Change[] $changes
     */
    public static function modify(
        Entry $result,
        array $changes,
        bool $isSystem = false,
    ): self {
        return new self(
            OperationType::Modify,
            $result,
            $changes,
            $isSystem,
        );
    }

    /**
     * The new RDN is read from the entry's DN, which the rename has already given it.
     */
    public static function modifyDn(
        Entry $result,
        bool $isSystem = false,
    ): self {
        return new self(
            OperationType::ModifyDn,
            $result,
            [],
            $isSystem,
        );
    }

    /**
     * Whether the write gives the entry its DN, which a modify leaves as it was.
     */
    public function namesEntry(): bool
    {
        return $this->operation !== OperationType::Modify;
    }

    /**
     * The names the client supplied: the entry's on an Add, the changes' on a Modify, the new RDN's on a rename.
     *
     * @return list<string>
     */
    public function suppliedNames(): array
    {
        return match ($this->operation) {
            OperationType::Add => array_map(
                static fn(Attribute $attribute): string => $attribute->getName(),
                array_values($this->entry->getAttributes()),
            ),
            OperationType::Modify => array_map(
                static fn(Change $change): string => $change->getAttribute()->getName(),
                array_values($this->changes),
            ),
            default => array_map(
                static fn(Rdn $component): string => $component->getName(),
                array_values($this->entry->getDn()->getRdn()->getAll()),
            ),
        };
    }
}
