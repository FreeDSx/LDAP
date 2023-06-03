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

namespace integration\FreeDSx\Ldap;

use Exception;
use FreeDSx\Ldap\LdapClient;
use Symfony\Component\Process\Process;

class ServerTestCase extends LdapTestCase
{
    private Process $subject;

    private ?LdapClient $client;

    private string $serverMode = 'ldapserver';

    public function tearDown(): void
    {
        parent::tearDown();
        $this->stopServer();
    }

    protected function authenticate(): void
    {
        $this->ldapClient()->bind(
            'cn=user,dc=foo,dc=bar',
            '12345'
        );
    }

    protected function waitForServerOutput(string $marker): string
    {
        $maxWait = 10;
        $i = 0;

        while ($this->subject->isRunning()) {
            $output = $this->subject->getOutput();
            $this->subject->clearOutput();

            if (str_contains($output, $marker)) {
                return $output;
            }

            $i++;
            if ($i === $maxWait) {
                break;
            }

            sleep(1);
        }

        throw new Exception(sprintf(
            'The expected output (%s) was not received after %d seconds.',
            $marker,
            $i
        ));
    }

    protected function createServerProcess(
        string $transport,
        ?string $handler = null
    ): void {
        $processArgs = [
            'php',
            __DIR__ . '/../../../bin/' . $this->serverMode . '.php',
            $transport,
        ];

        if ($handler) {
            $processArgs[] = $handler;
        }

        $this->subject = new Process($processArgs);
        $this->subject->start();
        $this->waitForServerOutput('server starting...');

        $useSsl = false;
        $servers = '127.0.0.1';

        if ($transport === 'ssl') {
            $transport = 'tcp';
            $useSsl = true;
        }
        if ($transport === 'unix') {
            $servers = '/var/run/ldap.socket';
        }

        $this->client = $this->getClient([
            'port' => 3389,
            'transport' => $transport,
            'servers' => $servers,
            'ssl_validate_cert' => false,
            'use_ssl' => $useSsl,
        ]);
    }

    protected function stopServer(): void
    {
        $this->ldapClient()->unbind();
        $this->client = null;
        $this->subject->stop();
    }

    protected function setServerMode(string $mode): void
    {
        $this->serverMode = $mode;
    }

    protected function ldapClient(): LdapClient
    {
        return $this->client ?? throw new \RuntimeException('The test LDAP client is not set.');
    }
}
