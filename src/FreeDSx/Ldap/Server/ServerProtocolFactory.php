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

namespace FreeDSx\Ldap\Server;

use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Server\Logging\ConnectionContext;
use FreeDSx\Socket\Socket;

/**
 * Adapts the container-built connection graph to the protocol factory contract used by the runners.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ServerProtocolFactory implements ServerProtocolFactoryInterface
{
    public function __construct(
        private ConnectionHandlerBuilderInterface $builder,
    ) {}

    public function make(
        Socket $socket,
        ConnectionContext $context = new ConnectionContext(),
    ): ServerProtocolHandler {
        return $this->builder->build(
            $socket,
            $context,
        );
    }
}
