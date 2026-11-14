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

namespace FreeDSx\Ldap\Server\Initialization\Requirement;

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\Initialization\RequirementInterface;
use FreeDSx\Ldap\ServerOptions;

use function sprintf;

/**
 * A read-only replica needs a database behind it.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ReplicaStorageRequirement implements RequirementInterface
{
    public function __construct(private ServerOptions $options) {}

    public function assertMet(): void
    {
        $storageConfig = $this->options->getStorageConfig();

        if ($this->options->getConsumerConfig() === null || $storageConfig instanceof PdoConfig) {
            return;
        }

        // The write-heavy apply path and the cross-process password-policy state both need a database.
        throw new RuntimeException(sprintf(
            'A read-only replica requires PDO storage, but "%s" is configured.',
            $storageConfig::class,
        ));
    }
}
