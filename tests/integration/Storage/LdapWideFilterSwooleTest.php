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
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\Query\WideFilterTestsTrait;

/**
 * Wide filters against in-memory storage on Swoole.
 */
final class LdapWideFilterSwooleTest extends ServerTestCase
{
    use WideFilterTestsTrait;

    public function setUp(): void
    {
        $this->requireSwoole();
        $this->setServerMode('ldap-backend-storage');

        parent::setUp();
    }

    protected static function storageExtraArgs(): array
    {
        return [
            '--storage=memory',
            '--runner=swoole',
        ];
    }
}
