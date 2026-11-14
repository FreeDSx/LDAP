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
use FreeDSx\Ldap\Server\Initialization\RequirementInterface;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\ServerListenerOptionsInterface;
use FreeDSx\Ldap\ServerOptions;

use function in_array;

/**
 * Swoole cannot capture a client's certificate, leaving its runner unable to verify one or offer SASL EXTERNAL.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class SwooleClientCertificatesRequirement implements RequirementInterface
{
    public function __construct(private ServerListenerOptionsInterface $options) {}

    public function assertMet(): void
    {
        if (!$this->options->isRunnerMode(RunnerMode::Swoole)) {
            return;
        }

        if ($this->options->getNetworkConfig()->isSslValidateCert()) {
            throw new RuntimeException(
                'The Swoole runner cannot verify client certificates. Unset sslValidateCert or use the PCNTL runner.',
            );
        }

        if (in_array(ServerOptions::SASL_EXTERNAL, $this->options->getSaslMechanisms(), true)) {
            throw new RuntimeException(
                'The Swoole runner cannot support the EXTERNAL SASL mechanism. Remove it or use the PCNTL runner.',
            );
        }
    }
}
