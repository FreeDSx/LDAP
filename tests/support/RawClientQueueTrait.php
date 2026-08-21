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

use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Socket\SocketOptions;
use FreeDSx\Socket\SocketPool;
use FreeDSx\Socket\SocketPoolOptions;

/**
 * A queue onto the test server, for assertions the client cannot make because it throws on an error result.
 */
trait RawClientQueueTrait
{
    private function rawQueue(): ClientQueue
    {
        return new ClientQueue(new SocketPool(
            (new SocketPoolOptions(
                (new SocketOptions())
                    ->setPort(TestWorker::port())
                    ->setTimeoutConnect(1),
            ))->setServers(['127.0.0.1']),
        ));
    }
}
