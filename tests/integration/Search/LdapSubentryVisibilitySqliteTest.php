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

namespace Tests\Integration\FreeDSx\Ldap\Search;

/**
 * The visibility suite against SQL storage, where exclusion is a query predicate and the size limit is pushed down.
 */
final class LdapSubentryVisibilitySqliteTest extends LdapSubentryVisibilityTest
{
    /**
     * @return list<string>
     */
    protected static function storageExtraArgs(): array
    {
        return [
            '--seed=' . self::seedLdif(),
            '--storage=sqlite',
        ];
    }
}
