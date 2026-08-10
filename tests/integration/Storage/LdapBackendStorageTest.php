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

namespace Tests\Integration\FreeDSx\Ldap\Storage;

use Tests\Integration\FreeDSx\Ldap\ServerTestCase;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\BindTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\ControlTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\DefaultAclTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\QueryTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\WriteTestsTrait;

/**
 * Backend behavior shared by every storage adapter.
 *
 * Subclasses override storageExtraArgs() to route the shared server at a different backend, so the same cases run
 * against each one. Cases live in the Concern traits grouped by the behavior they cover.
 */
class LdapBackendStorageTest extends ServerTestCase
{
    use BindTestsTrait;
    use QueryTestsTrait;
    use DefaultAclTestsTrait;
    use WriteTestsTrait;
    use ControlTestsTrait;

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldap-backend-storage',
            'tcp',
            static::storageExtraArgs(),
        );
    }

    public static function tearDownAfterClass(): void
    {
        parent::tearDownAfterClass();
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        $this->setServerMode('ldap-backend-storage');

        parent::setUp();
    }

    /**
     * Hook for subclasses to route the shared server through a different backend.
     *
     * @return list<string>
     */
    protected static function storageExtraArgs(): array
    {
        return [];
    }
}
