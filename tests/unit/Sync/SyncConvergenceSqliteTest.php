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

namespace Tests\Unit\FreeDSx\Ldap\Sync;

use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\Config\Storage\StorageConfigInterface;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Sync\Convergence\ConvergenceProvider;
use Tests\Support\FreeDSx\Ldap\Sync\SyncConvergenceTests;

final class SyncConvergenceSqliteTest extends TestCase
{
    use SyncConvergenceTests;

    protected function storage(): StorageConfigInterface
    {
        return PdoConfig::forSqlite(':memory:');
    }

    protected static function seedCount(): int
    {
        return 200;
    }

    /**
     * Known gaps: a link cannot follow an entry outside the content, nor one moved while the sync read its group.
     */
    protected function unfollowedMembers(ConvergenceProvider $provider): array
    {
        return $provider->everHidden() + $provider->movedMidFetch();
    }
}
