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

namespace FreeDSx\Ldap\Server\Initialization;

use FreeDSx\Ldap\Server\Logging\ConcurrencyLimitReason;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\ServerEvent;

/**
 * An event to record about the configuration the server starts with.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class InitializationWarning
{
    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public ServerEvent $event,
        public array $context = [],
    ) {}

    /**
     * @param array<string, mixed> $context
     */
    public static function concurrencyLimited(
        ConcurrencyLimitReason $reason,
        array $context = [],
    ): self {
        return new self(
            ServerEvent::ConcurrencyLimited,
            [EventContext::REASON => $reason->value] + $context,
        );
    }
}
