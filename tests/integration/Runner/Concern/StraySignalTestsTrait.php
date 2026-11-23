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

namespace Tests\Integration\FreeDSx\Ldap\Runner\Concern;

use function posix_kill;
use function usleep;

trait StraySignalTestsTrait
{
    public function testASigusr1SentToEveryServerProcessKeepsServingItsSessionsAndNewClients(): void
    {
        $this->requirePosix();
        $this->createServerProcess('tcp');
        $session = $this->buildClient('tcp');
        $session->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        foreach ([$this->serverPid(), ...$this->serverChildPids()] as $pid) {
            posix_kill(
                $pid,
                SIGUSR1,
            );
        }
        usleep(250_000);

        self::assertTrue(
            $this->isServerRunning(),
            'The server must remain running after SIGUSR1.',
        );
        self::assertSame(
            'dn:cn=user,dc=foo,dc=bar',
            $session->whoami(),
        );

        $newClient = $this->buildClient('tcp');
        $newClient->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );
        self::assertSame(
            'dn:cn=user,dc=foo,dc=bar',
            $newClient->whoami(),
        );
    }
}
