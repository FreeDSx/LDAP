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

namespace FreeDSx\Ldap\Sync\Consumer;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use Psr\Log\LoggerInterface;

use function count;

/**
 * Leaves out the replicated linked values a replica cannot store.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class LinkedValueFilter
{
    public function __construct(
        private LinkedAttributes $linked,
        private ?LoggerInterface $logger = null,
    ) {}

    /**
     * The entry without the linked values no store could keep, copied only when one is left out.
     */
    public function storable(Entry $entry): Entry
    {
        $filtered = null;

        foreach ($entry->getAttributes() as $attribute) {
            if (!$this->linked->links($attribute) || !$this->linked->carriesUid($attribute->getName())) {
                continue;
            }
            $kept = $this->storableValuesOf($attribute);

            if (count($kept) === count($attribute->getValues())) {
                continue;
            }

            $filtered ??= $entry->makeCopy();
            $this->keep(
                $filtered,
                $attribute->getName(),
                $kept,
            );
            $this->logger?->warning(
                'A replicated value carries a uid longer than can be stored and was left out.',
                [
                    'dn' => $entry->getDn()->toString(),
                    'attribute' => $attribute->getName(),
                ],
            );
        }

        return $filtered ?? $entry;
    }

    /**
     * @return list<string>
     */
    private function storableValuesOf(Attribute $attribute): array
    {
        $kept = [];

        foreach ($attribute->getValues() as $value) {
            if ($this->linked->targetOf($attribute->getName(), $value)->isStorable()) {
                $kept[] = $value;
            }
        }

        return $kept;
    }

    /**
     * @param list<string> $values
     */
    private function keep(
        Entry $entry,
        string $name,
        array $values,
    ): void {
        if ($values === []) {
            $entry->reset($name);

            return;
        }

        $entry->set(
            $name,
            ...$values,
        );
    }
}
