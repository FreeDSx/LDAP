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

namespace Tests\Support\FreeDSx\Ldap\Server\Configuration;

use FreeDSx\Ldap\Server\Configuration\ConfigReloaderInterface;
use FreeDSx\Ldap\ServerOptions;
use RuntimeException;

/**
 * Reloads from a flag file: anonymous bind is enabled when it contains "allow-anonymous", and "invalid" fails the reload.
 */
final readonly class FileFlagConfigReloader implements ConfigReloaderInterface
{
    public function __construct(private string $flagFile) {}

    public function reload(ServerOptions $current): ServerOptions
    {
        $flag = is_file($this->flagFile)
            ? trim((string) file_get_contents($this->flagFile))
            : '';

        if ($flag === 'invalid') {
            throw new RuntimeException('The configuration flag file is invalid.');
        }

        fwrite(STDOUT, 'configuration reloaded...' . PHP_EOL);

        return (clone $current)->setAllowAnonymous($flag === 'allow-anonymous');
    }
}
