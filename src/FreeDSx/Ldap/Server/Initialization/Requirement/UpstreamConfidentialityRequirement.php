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
use FreeDSx\Ldap\ProxyOptions;
use FreeDSx\Ldap\Server\Initialization\RequirementInterface;

/**
 * A proxy that requires a confidential upstream must encrypt its upstream connection.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class UpstreamConfidentialityRequirement implements RequirementInterface
{
    public function __construct(private ProxyOptions $options) {}

    public function assertMet(): void
    {
        if (!$this->options->getRequireUpstreamConfidentiality()) {
            return;
        }
        if ($this->options->getClientOptions()->isUseSsl() || $this->options->getUseStartTls()) {
            return;
        }

        throw new RuntimeException(
            'The upstream connection is not encrypted. Set useSsl or useStartTls on it, '
            . 'or unset requireUpstreamConfidentiality.',
        );
    }
}
