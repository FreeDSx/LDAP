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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoSchemaDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterResult;

/**
 * No substring index: indexes nothing, so a substring filter falls back to scanning the sidecar.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class NoSubstringIndex implements SubstringIndexInterface
{
    public function schemaStatements(PdoSchemaDialectInterface $dialect): array
    {
        return [];
    }

    public function indexes(string $attributeLower): bool
    {
        return false;
    }

    public function readsOriginalValue(string $attributeLower): bool
    {
        return false;
    }

    public function maintain(
        int $entryId,
        Entry $entry,
        callable $execute,
    ): void {}

    public function buildSubstringPredicate(
        string $attributeLower,
        array $fragments,
    ): ?SqlFilterResult {
        return null;
    }
}
