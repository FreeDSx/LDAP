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

namespace Tests\Support\FreeDSx\Ldap;

use function extension_loaded;
use function sprintf;

/**
 * Skips a test whose subject cannot run without an optional extension.
 */
trait RequiresExtensionsTrait
{
    protected function requireSwoole(): void
    {
        $this->requireExtension('swoole');
    }

    protected function requirePcntl(): void
    {
        $this->requireExtension('pcntl');
    }

    protected function requirePosix(): void
    {
        $this->requireExtension('posix');
    }

    private function requireExtension(string $extension): void
    {
        if (extension_loaded($extension)) {
            return;
        }

        self::markTestSkipped(sprintf(
            'The %s extension is required for this test.',
            $extension,
        ));
    }
}
