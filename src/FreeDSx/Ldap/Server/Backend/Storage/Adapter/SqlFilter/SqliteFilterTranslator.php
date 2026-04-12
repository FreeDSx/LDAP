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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter;

/**
 * Translates LDAP filters into SQLite-compatible SQL WHERE clause fragments.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SqliteFilterTranslator implements FilterTranslatorInterface
{
    use SqlFilterTranslatorTrait;

    protected function buildPresenceCheck(string $attribute): string
    {
        return "json_type(attributes, '$.\"{$attribute}\"') IS NOT NULL";
    }

    protected function buildValueExists(
        string $attribute,
        string $innerCondition,
    ): string {
        return "EXISTS (SELECT 1 FROM json_each(attributes, '$.\"{$attribute}\".values') WHERE {$innerCondition})";
    }

    protected function valueAlias(): string
    {
        return 'value';
    }
}
