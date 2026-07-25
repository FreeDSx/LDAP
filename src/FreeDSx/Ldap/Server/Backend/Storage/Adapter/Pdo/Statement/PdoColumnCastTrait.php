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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement;

use function is_numeric;
use function is_string;

/**
 * Narrows loosely-typed PDO fetched column values to their expected scalar type.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait PdoColumnCastTrait
{
    private function stringColumn(mixed $value): string
    {
        return is_string($value)
            ? $value
            : '';
    }

    private function intColumn(mixed $value): int
    {
        return is_numeric($value)
            ? (int) $value
            : 0;
    }
}
